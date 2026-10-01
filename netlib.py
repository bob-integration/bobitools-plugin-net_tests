#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 BOBI SAS, France
# Auteur : Cyril Mazouer, pour le compte de BOBI SAS
# Distribué sous licence GNU GPL v3 (ou ultérieure) ; voir le fichier LICENSE.

"""Les sondes de l'outil « Tests réseau », séparées de la couche HTTP.

Chaque fonction rend une STRUCTURE, jamais du texte à relire. C'est le choix central de ce
fichier : les binaires `ping` et `traceroute` existent, mais leur sortie est localisée, variable
d'une distribution à l'autre, et il faudrait la réanalyser à chaque changement d'image. Ici on
parle ICMP directement — mesuré, un conteneur Docker reçoit CAP_NET_RAW par défaut, donc
`SOCK_RAW` fonctionne — et l'on rend des nombres.

Aucune de ces fonctions ne construit de ligne de commande : rien de ce que l'utilisateur saisit
n'atteint un interpréteur. Les cibles sont validées AVANT usage (cf. `cible_valide`).
"""
import ipaddress
import os
import re
import select
import socket
import ssl
import struct
import time
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _Delai

# ── Bornes. Elles ne sont pas décoratives : ce service tourne sur le serveur, et une sonde sans
# plafond est un moyen de le saturer ou d'inonder un tiers depuis notre adresse.
MAX_COUNT = 50            # paquets d'un ping
MAX_HOPS = 40             # sauts d'un traceroute
MAX_TIMEOUT = 10.0        # secondes, par tentative
MAX_ECOUTE = 60.0         # secondes, écoute multicast
MAX_BALAYAGE = 1024       # adresses d'un balayage (= un /22)
MAX_PORTS = 64            # ports testés en une fois

ICMP_ECHO = 8
ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11
ICMP_UNREACH = 3


class SondeError(Exception):
    """Refus explicite d'une sonde. Le message est destiné à l'écran, pas au journal."""


# ─── Validation des cibles ──────────────────────────────────────────────────
# Un nom d'hôte, une adresse, rien d'autre. Le tiret initial est refusé explicitement : c'est la
# forme qui, passée un jour à un binaire, se ferait prendre pour une option (« -f »). Aucun
# binaire n'est appelé ici aujourd'hui, mais la garde ne coûte rien et survit au refactor qui,
# lui, oubliera pourquoi.
_NOM = re.compile(r"^(?!-)[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")


def cible_valide(h):
    """Nom d'hôte ou adresse IP, nettoyé. Lève SondeError sinon."""
    h = str(h or "").strip()
    if not h:
        raise SondeError("cible attendue (nom d'hôte ou adresse IP).")
    if len(h) > 253:
        raise SondeError("cible trop longue.")
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    # Une suite de chiffres et de points qui n'est pas une IP est une IP MAL TAPÉE, pas un nom
    # d'hôte — même si la syntaxe des noms l'autorise. Le dire évite un « ne se résout pas »
    # trompeur, qui envoie chercher du côté du DNS.
    if re.fullmatch(r"[0-9.]+", h):
        raise SondeError("« %s » ressemble à une adresse IP mal formée." % h[:60])
    if not _NOM.match(h):
        raise SondeError("« %s » n'est ni une adresse IP ni un nom d'hôte valide." % h[:60])
    return h


def resoudre(h):
    """(ip, nom_canonique). Lève SondeError si le nom ne se résout pas — c'est déjà un résultat
    de test, et il doit se lire comme tel plutôt que comme une panne de l'outil."""
    h = cible_valide(h)
    try:
        ipaddress.ip_address(h)
        return h, None
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(h, None, socket.AF_INET, socket.SOCK_DGRAM)
    except socket.gaierror as e:
        raise SondeError("« %s » ne se résout pas (%s)." % (h, e.strerror or e))
    return infos[0][4][0], infos[0][3] or None


def _borne(v, defaut, lo, hi, entier=True):
    try:
        x = (int if entier else float)(v)
    except (TypeError, ValueError):
        return defaut
    return max(lo, min(hi, x))


def _somme_controle(data):
    """Complément à un sur 16 bits, tel que le veut la RFC 1071."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _paquet_echo(ident, seq, charge=32):
    corps = struct.pack("!BBHHH", ICMP_ECHO, 0, 0, ident, seq) + bytes(range(charge % 256))[:charge]
    return corps[:2] + struct.pack("!H", _somme_controle(corps)) + corps[4:]


def _lire_icmp(paquet):
    """(type, code, ident, seq, dst) d'une trame IP reçue sur un socket brut, ou None.
    `dst` = destination du paquet d'origine (TIME_EXCEEDED / UNREACH), None pour un écho.

    Deux cas se présentent, et les confondre fait attribuer une réponse au mauvais paquet :
    un ECHO_REPLY porte directement son identifiant, tandis qu'un TIME_EXCEEDED transporte en
    charge utile l'en-tête IP d'origine SUIVI des huit premiers octets de notre propre ICMP —
    c'est là, et là seulement, qu'on retrouve à qui il répond."""
    if len(paquet) < 20:
        return None
    ihl = (paquet[0] & 0x0F) * 4
    icmp = paquet[ihl:]
    if len(icmp) < 8:
        return None
    typ, code = icmp[0], icmp[1]
    if typ == ICMP_ECHO_REPLY:
        ident, seq = struct.unpack("!HH", icmp[4:8])
        return typ, code, ident, seq, None
    if typ in (ICMP_TIME_EXCEEDED, ICMP_UNREACH):
        interne = icmp[8:]
        if len(interne) < 20:
            return typ, code, None, None, None
        # Destination du paquet d'ORIGINE : c'est elle qui dit à quelle cible ce message
        # répond — l'émetteur du message, lui, est le routeur qui l'a produit.
        dst = socket.inet_ntoa(interne[16:20])
        ihl2 = (interne[0] & 0x0F) * 4
        orig = interne[ihl2:]
        if len(orig) < 8:
            return typ, code, None, None, dst
        ident, seq = struct.unpack("!HH", orig[4:8])
        return typ, code, ident, seq, dst
    return None


# Identifiant ICMP : UN PAR APPEL, jamais dérivé du PID. Ces sondes tournent dans le processus
# de l'app (runtime in-process), où tous les appels concurrents partagent le même PID : avec
# l'ancien `os.getpid()`, un balayage lançant 64 pings simultanés (tous seq=1) créditait à
# l'hôte A l'écho de l'hôte B — un hôte muet ressortait « vivant ». L'identifiant ne suffit
# d'ailleurs pas seul (16 bits, et d'autres programmes pingent aussi) : la réponse doit en
# plus venir de l'adresse visée, cf. ping().
_ident_lock = threading.Lock()
_ident_suivant = [int.from_bytes(os.urandom(2), "big")]


def _nouvel_ident():
    with _ident_lock:
        _ident_suivant[0] = (_ident_suivant[0] + 1) & 0xFFFF
        return _ident_suivant[0]


def _socket_icmp():
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        raise SondeError("ICMP indisponible : le conteneur n'a pas la capacité NET_RAW. "
                         "Ping et traceroute en dépendent ; les autres tests fonctionnent.")


# ─── Ping ───────────────────────────────────────────────────────────────────
def ping(cible, count=4, timeout=1.0, intervalle=0.25, charge=32):
    """Aller-retour ICMP, paquet par paquet.

    On rend CHAQUE tentative, pas seulement la moyenne : une perte isolée au milieu d'une série
    régulière et une série qui se dégrade racontent deux pannes différentes, et la moyenne les
    rend identiques."""
    ip, nom = resoudre(cible)
    count = _borne(count, 4, 1, MAX_COUNT)
    timeout = _borne(timeout, 1.0, 0.1, MAX_TIMEOUT, entier=False)
    intervalle = _borne(intervalle, 0.25, 0.0, 2.0, entier=False)
    charge = _borne(charge, 32, 0, 1400)
    ident = _nouvel_ident()
    s = _socket_icmp()
    essais = []
    try:
        s.settimeout(timeout)
        for seq in range(1, count + 1):
            if seq > 1 and intervalle:
                time.sleep(intervalle)
            t0 = time.time()
            try:
                s.sendto(_paquet_echo(ident, seq, charge), (ip, 0))
            except OSError as e:
                essais.append({"seq": seq, "ok": False, "error": str(e)})
                continue
            fin = t0 + timeout
            recu = None
            while time.time() < fin:
                reste = fin - time.time()
                r, _, _ = select.select([s], [], [], max(0.0, reste))
                if not r:
                    break
                paquet, src = s.recvfrom(2048)
                lu = _lire_icmp(paquet)
                if not lu:
                    continue
                typ, code, i2, s2, dst = lu
                if typ == ICMP_ECHO_REPLY and i2 == ident and s2 == seq and src[0] == ip:
                    recu = {"seq": seq, "ok": True, "ms": round((time.time() - t0) * 1000, 3),
                            "from": src[0]}
                    break
                if typ == ICMP_UNREACH and i2 == ident and s2 == seq and dst == ip:
                    recu = {"seq": seq, "ok": False, "unreachable": True, "from": src[0],
                            "error": "injoignable (code ICMP %d)" % code}
                    break
            essais.append(recu or {"seq": seq, "ok": False, "error": "délai dépassé"})
    finally:
        s.close()
    rtt = [e["ms"] for e in essais if e.get("ok")]
    return {
        "target": cible, "ip": ip, "hostname": nom,
        "sent": len(essais), "received": len(rtt),
        "loss_pct": round(100.0 * (len(essais) - len(rtt)) / max(1, len(essais)), 1),
        "min_ms": min(rtt) if rtt else None,
        "avg_ms": round(sum(rtt) / len(rtt), 3) if rtt else None,
        "max_ms": max(rtt) if rtt else None,
        # L'écart-type dit si la latence est STABLE. Une moyenne de 3 ms qui oscille entre 1 et
        # 40 n'a pas le même sens qu'une moyenne de 3 ms toujours à 3 — et c'est la seconde
        # qu'on attend d'un fabric.
        "jitter_ms": round((sum((x - sum(rtt) / len(rtt)) ** 2 for x in rtt) / len(rtt)) ** 0.5, 3)
                     if len(rtt) > 1 else None,
        "attempts": essais,
    }


# ─── Traceroute ─────────────────────────────────────────────────────────────
def traceroute(cible, max_hops=20, timeout=1.5, essais_par_saut=2):
    """Chemin aller, saut par saut, en ICMP echo à TTL croissant.

    ICMP plutôt qu'UDP : c'est ce que fait `tracert` sous Windows, et c'est ce qui passe le mieux
    sur les équipements réseau qui filtrent les ports UDP hauts. Un saut muet (« * ») n'est PAS
    une panne : beaucoup de routeurs ne renvoient simplement pas de TTL expiré."""
    ip, nom = resoudre(cible)
    max_hops = _borne(max_hops, 20, 1, MAX_HOPS)
    timeout = _borne(timeout, 1.5, 0.1, MAX_TIMEOUT, entier=False)
    essais_par_saut = _borne(essais_par_saut, 2, 1, 5)
    ident = _nouvel_ident()
    s = _socket_icmp()
    sauts, atteint, seq = [], False, 0
    try:
        for ttl in range(1, max_hops + 1):
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            mesures, qui = [], None
            for _ in range(essais_par_saut):
                seq += 1
                t0 = time.time()
                try:
                    s.sendto(_paquet_echo(ident, seq, 32), (ip, 0))
                except OSError as e:
                    mesures.append(None)
                    sauts.append({"ttl": ttl, "error": str(e)})
                    continue
                fin, vu = t0 + timeout, None
                while time.time() < fin:
                    r, _, _ = select.select([s], [], [], max(0.0, fin - time.time()))
                    if not r:
                        break
                    paquet, src = s.recvfrom(2048)
                    lu = _lire_icmp(paquet)
                    if not lu:
                        continue
                    typ, _code, i2, s2, dst = lu
                    if i2 != ident or s2 != seq:
                        continue
                    # Un écho ne compte que s'il vient de la cible ; un TTL expiré, que s'il
                    # parle d'un paquet envoyé à la cible.
                    if typ == ICMP_ECHO_REPLY and src[0] != ip:
                        continue
                    if typ != ICMP_ECHO_REPLY and dst not in (None, ip):
                        continue
                    vu = (round((time.time() - t0) * 1000, 3), src[0],
                          typ == ICMP_ECHO_REPLY)
                    break
                if vu:
                    mesures.append(vu[0])
                    qui = qui or vu[1]
                    atteint = atteint or vu[2]
                else:
                    mesures.append(None)
            sauts.append({
                "ttl": ttl, "ip": qui,
                "hostname": _nom_inverse(qui) if qui else None,
                "ms": [m for m in mesures],
                "avg_ms": round(sum(x for x in mesures if x) / len([x for x in mesures if x]), 3)
                          if any(mesures) else None,
            })
            if atteint:
                break
    finally:
        s.close()
    return {"target": cible, "ip": ip, "hostname": nom, "reached": atteint,
            "hops": sauts, "max_hops": max_hops}


# Résolution inverse bornée SANS `socket.setdefaulttimeout` : ce réglage est GLOBAL au processus,
# et ces sondes tournent dans celui de l'app — le poser, même une seconde, changeait le délai de
# toutes les sockets ouvertes entre-temps (provider Ember+ compris), et le remettre à None
# écrasait ce qu'un autre module avait pu y mettre. `gethostbyaddr` ne prend pas de délai :
# on l'attend donc au plus une seconde depuis un petit pool, et on abandonne la réponse au-delà.
_POOL_PTR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="net_tests-ptr")


def _nom_inverse(ip, delai=1.0):
    """Nom inverse, au mieux : un PTR absent est la norme sur un réseau interne, pas une erreur."""
    if not ip:
        return None
    try:
        return _POOL_PTR.submit(socket.gethostbyaddr, ip).result(timeout=delai)[0]
    except (_Delai, OSError, socket.herror):
        return None


# ─── Port TCP ───────────────────────────────────────────────────────────────
def tcp(cible, ports, timeout=2.0):
    """Ouverture d'un ou plusieurs ports TCP, avec le temps d'établissement.

    On distingue REFUSÉ (quelque chose répond « non », donc l'hôte est vivant et le chemin
    ouvert) de DÉLAI DÉPASSÉ (rien ne répond : port filtré, ou hôte absent). Les confondre en un
    seul « fermé » fait chercher un pare-feu là où il n'y a qu'un service arrêté."""
    ip, nom = resoudre(cible)
    if isinstance(ports, (int, str)):
        ports = [ports]
    liste = []
    for p in (ports or []):
        try:
            n = int(p)
        except (TypeError, ValueError):
            continue
        if 1 <= n <= 65535 and n not in liste:
            liste.append(n)
    if not liste:
        raise SondeError("au moins un port entre 1 et 65535 est attendu.")
    if len(liste) > MAX_PORTS:
        raise SondeError("%d ports au maximum en une fois (%d demandés)." % (MAX_PORTS, len(liste)))
    timeout = _borne(timeout, 2.0, 0.1, MAX_TIMEOUT, entier=False)

    def un(port):
        t0 = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            return {"port": port, "state": "open", "ms": round((time.time() - t0) * 1000, 3)}
        except socket.timeout:
            return {"port": port, "state": "filtered", "detail": "délai dépassé"}
        except ConnectionRefusedError:
            return {"port": port, "state": "closed", "detail": "connexion refusée",
                    "ms": round((time.time() - t0) * 1000, 3)}
        except OSError as e:
            return {"port": port, "state": "error", "detail": str(e)}
        finally:
            s.close()

    with ThreadPoolExecutor(max_workers=min(16, len(liste))) as ex:
        res = sorted(ex.map(un, liste), key=lambda d: d["port"])
    return {"target": cible, "ip": ip, "hostname": nom, "ports": res,
            "open": [r["port"] for r in res if r["state"] == "open"]}


# ─── TLS ────────────────────────────────────────────────────────────────────
def tls(cible, port=443, timeout=5.0, sni=None):
    """Certificat présenté par le service : émetteur, validité, noms couverts.

    La vérification est DÉSACTIVÉE volontairement : sur un parc, les équipements portent des
    certificats auto-signés, et refuser de les lire priverait justement de l'information qu'on
    vient chercher — sa date d'expiration. On rapporte donc ce qui est présenté, et l'on dit
    séparément si la chaîne aurait été acceptée."""
    ip, _nom = resoudre(cible)
    port = _borne(port, 443, 1, 65535)
    timeout = _borne(timeout, 5.0, 0.5, MAX_TIMEOUT, entier=False)
    hote = sni or cible
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t0 = time.time()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as brut:
            with ctx.wrap_socket(brut, server_hostname=hote) as tls_sock:
                cert = tls_sock.getpeercert(binary_form=False)
                der = tls_sock.getpeercert(binary_form=True)
                version, chiffre = tls_sock.version(), tls_sock.cipher()
    except socket.timeout:
        raise SondeError("%s:%d — délai dépassé (port filtré, ou hôte absent)." % (ip, port))
    except ConnectionRefusedError:
        raise SondeError("%s:%d — connexion refusée : rien n'écoute sur ce port." % (ip, port))
    except ssl.SSLError as e:
        raise SondeError("%s:%d répond, mais pas en TLS (%s)." % (ip, port, e.reason or e))
    except OSError as e:
        raise SondeError("%s:%d — %s" % (ip, port, e.strerror or e))
    ms = round((time.time() - t0) * 1000, 3)
    # getpeercert() ne décode les champs QUE si la vérification est active. Sans elle on n'a que
    # le DER — on le repasse donc dans un contexte vérifiant pour obtenir les champs, sans quoi
    # l'écran n'aurait qu'une empreinte binaire à montrer.
    infos = _decoder_cert(der)
    reste = None
    if infos.get("not_after_ts"):
        reste = int((infos["not_after_ts"] - time.time()) // 86400)
    return {"target": cible, "ip": ip, "port": port, "sni": hote, "ms": ms,
            "tls_version": version,
            "cipher": chiffre[0] if chiffre else None,
            "cert": infos, "days_left": reste,
            "expired": reste is not None and reste < 0,
            "verified": _chaine_valide(ip, port, hote, timeout),
            "raw_available": bool(cert or der)}


def _decoder_cert(der):
    """Champs lisibles d'un certificat DER. `ssl` sait le faire seul depuis 3.10 via
    `_ssl._test_decode_cert`, qui exige un fichier ; on passe donc par un fichier temporaire en
    mémoire vive plutôt que d'embarquer une bibliothèque ASN.1 pour trois champs."""
    import tempfile
    if not der:
        return {}
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(pem)
            chemin = f.name
        try:
            d = ssl._ssl._test_decode_cert(chemin)
        finally:
            os.unlink(chemin)
    except (ssl.SSLError, OSError, AttributeError):
        return {}

    def plat(champ):
        return {k: v for paire in (d.get(champ) or ()) for (k, v) in paire}

    def ts(txt):
        try:
            return ssl.cert_time_to_seconds(txt)
        except (ValueError, TypeError):
            return None

    return {
        "subject": plat("subject"), "issuer": plat("issuer"),
        "not_before": d.get("notBefore"), "not_after": d.get("notAfter"),
        "not_after_ts": ts(d.get("notAfter")),
        "serial": d.get("serialNumber"),
        "san": [v for (t, v) in (d.get("subjectAltName") or ()) if t == "DNS"],
    }


def _chaine_valide(ip, port, hote, timeout):
    """La chaîne serait-elle acceptée par un client ordinaire ? Question distincte de « que
    contient le certificat » — et c'est celle qui prédit si un navigateur criera."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as b:
            with ctx.wrap_socket(b, server_hostname=hote):
                return True
    except (ssl.SSLError, ssl.CertificateError, OSError):
        return False


# ─── Interfaces de l'hôte ───────────────────────────────────────────────────
def interfaces():
    """Interfaces IPv4 de la machine : [{name, ip}], boucle locale exclue.

    Sert au choix de l'interface d'écoute multicast : sur un serveur à plusieurs pattes
    (administration, rouge, bleu), rejoindre un groupe « sur l'interface par défaut » rejoint
    celle de la route par défaut — presque toujours l'administration, donc pas le fabric."""
    import fcntl
    out = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _idx, nom in socket.if_nameindex():
            try:
                brut = fcntl.ioctl(s.fileno(), 0x8915,           # SIOCGIFADDR
                                   struct.pack("256s", nom[:15].encode()))
            except OSError:
                continue                                         # pas d'IPv4 sur cette patte
            ip = socket.inet_ntoa(brut[20:24])
            if not ip.startswith("127."):
                out.append({"name": nom, "ip": ip})
    finally:
        s.close()
    return out


# ─── Multicast ──────────────────────────────────────────────────────────────
def multicast(groupe, port, secondes=5.0, interface=None):
    """Rejoint un groupe multicast et COMPTE ce qui arrive.

    ⚠ Rejoindre est un ACTE RÉSEAU, pas une observation passive : l'IGMP join fait livrer le
    flux par le switch jusqu'au port du serveur. Une essence vidéo ST 2110 pèse plusieurs Gb/s
    — de quoi saturer une patte d'administration le temps de l'écoute. D'où la durée bornée
    (MAX_ECOUTE), le retrait explicite du groupe en sortie, et l'avertissement que l'UI porte.

    Le point de vue est celui de la machine qui exécute : en conteneur ponté, le multicast du
    LAN ne traverse pas le NAT et l'absence de paquets n'y prouve rien — d'où le drapeau
    `bridged`, faux quand l'outil tourne dans le processus de l'app, sur l'hôte."""
    g = cible_valide(groupe)
    try:
        adr = ipaddress.ip_address(g)
    except ValueError:
        raise SondeError("le groupe multicast doit être une adresse, pas un nom.")
    if adr.version != 4 or not adr.is_multicast:
        raise SondeError("%s n'est pas une adresse multicast (224.0.0.0 à 239.255.255.255)." % g)
    if interface:
        try:
            interface = str(ipaddress.IPv4Address(str(interface).strip()))
        except ValueError:
            raise SondeError("l'interface d'écoute se désigne par son adresse IPv4.")
        if interface not in {i["ip"] for i in interfaces()}:
            raise SondeError("%s n'est l'adresse d'aucune interface de ce serveur." % interface)
    port = _borne(port, 5004, 1, 65535)
    secondes = _borne(secondes, 5.0, 1.0, MAX_ECOUTE, entier=False)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    mreq = struct.pack("4s4s", socket.inet_aton(g), socket.inet_aton(interface or "0.0.0.0"))
    joint = False
    sources, paquets, octets = {}, 0, 0
    try:
        # Lié au GROUPE, pas à « toutes adresses » : sur l'hôte, d'autres programmes ont pu
        # rejoindre d'autres groupes sur le même port, et un bind large mêlerait leurs paquets
        # aux nôtres dans le décompte.
        s.bind((g, port))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        joint = True
        fin = time.time() + secondes
        t0 = time.time()
        while time.time() < fin:
            r, _, _ = select.select([s], [], [], max(0.0, fin - time.time()))
            if not r:
                continue
            data, src = s.recvfrom(65535)
            paquets += 1
            octets += len(data)
            e = sources.setdefault(src[0], {"ip": src[0], "packets": 0, "bytes": 0})
            e["packets"] += 1
            e["bytes"] += len(data)
        duree = max(0.001, time.time() - t0)
    except OSError as e:
        raise SondeError("écoute impossible sur %s:%d — %s" % (g, port, e.strerror or e))
    finally:
        if joint:
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
            except OSError:
                pass
        s.close()
    return {"group": g, "port": port, "interface": interface, "seconds": round(duree, 2),
            "packets": paquets, "bytes": octets,
            "pps": round(paquets / duree, 1),
            "mbps": round(octets * 8 / duree / 1e6, 3),
            "sources": sorted(sources.values(), key=lambda d: -d["packets"]),
            "bridged": os.path.exists("/.dockerenv")}


# ─── Balayage de sous-réseau ────────────────────────────────────────────────
def balayage(cidr, ports=None, timeout=1.0, parallele=64):
    """Qui répond sur une plage. ICMP d'abord, puis TCP si des ports sont demandés.

    Un hôte muet en ICMP n'est PAS forcément absent : beaucoup de systèmes filtrent l'écho par
    défaut. C'est pourquoi un port TCP ouvert suffit à déclarer l'hôte vivant, indépendamment du
    ping — sans quoi un balayage sur un parc Windows rendrait une page blanche."""
    try:
        reseau = ipaddress.ip_network(str(cidr or "").strip(), strict=False)
    except ValueError as e:
        raise SondeError("plage invalide (%s). Forme attendue : 10.1.99.0/24." % e)
    if reseau.version != 4:
        raise SondeError("seul IPv4 est pris en charge pour l'instant.")
    hotes = list(reseau.hosts()) or [reseau.network_address]
    if len(hotes) > MAX_BALAYAGE:
        raise SondeError("%d adresses demandées, maximum %d (soit un /22). Découpez la plage."
                         % (len(hotes), MAX_BALAYAGE))
    liste = []
    for p in (ports or []):
        try:
            n = int(p)
        except (TypeError, ValueError):
            continue
        if 1 <= n <= 65535 and n not in liste:
            liste.append(n)
    liste = liste[:8]                       # un balayage n'est pas un scan de ports exhaustif
    timeout = _borne(timeout, 1.0, 0.1, 5.0, entier=False)
    parallele = _borne(parallele, 64, 1, 128)

    def un(ip):
        ip = str(ip)
        r = {"ip": ip, "alive": False, "ms": None, "ports": [], "hostname": None}
        p = ping(ip, count=1, timeout=timeout, intervalle=0)
        if p["received"]:
            r["alive"] = True
            r["ms"] = p["avg_ms"]
        if liste:
            t = tcp(ip, liste, timeout=timeout)
            r["ports"] = t["open"]
            if t["open"]:
                r["alive"] = True
        if r["alive"]:
            r["hostname"] = _nom_inverse(ip)
        return r

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=parallele) as ex:
        res = list(ex.map(un, hotes))
    vivants = [r for r in res if r["alive"]]
    return {"cidr": str(reseau), "scanned": len(hotes), "alive": len(vivants),
            "seconds": round(time.time() - t0, 2),
            "ports_tested": liste,
            "hosts": sorted(vivants, key=lambda d: [int(x) for x in d["ip"].split(".")])}


# ─── DNS ────────────────────────────────────────────────────────────────────
# dnspython plutôt qu'un client maison : `socket.getaddrinfo` ne sait rendre que des adresses,
# ne dit pas d'où vient la réponse, et ne permet pas d'interroger UN résolveur choisi — or
# « ça marche depuis mon poste mais pas depuis le serveur » se tranche précisément en comparant
# deux résolveurs sur la même question.
try:
    import dns.resolver
    import dns.reversename
    import dns.rdatatype
except ImportError:                        # l'outil reste utilisable sans, les autres sondes aussi
    dns = None

TYPES_DNS = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "PTR", "CAA"]


def dns_query(nom, type_="A", resolveur=None, timeout=3.0):
    """Interrogation DNS, avec le résolveur de son choix.

    Le temps de réponse est rendu au même titre que les enregistrements : un DNS qui répond juste
    mais en deux secondes casse tout ce qui l'interroge, et cela ne se voit pas dans la réponse."""
    if dns is None:
        raise SondeError("le module dnspython n'est pas disponible dans cette image.")
    type_ = str(type_ or "A").upper().strip()
    if type_ not in TYPES_DNS:
        raise SondeError("type inconnu : %s. Attendu parmi %s." % (type_[:12], ", ".join(TYPES_DNS)))
    timeout = _borne(timeout, 3.0, 0.5, MAX_TIMEOUT, entier=False)
    brut = str(nom or "").strip()
    if not brut:
        raise SondeError("nom à résoudre attendu.")

    r = dns.resolver.Resolver()
    if resolveur:
        ip_res = cible_valide(resolveur)
        try:
            ipaddress.ip_address(ip_res)
        except ValueError:
            ip_res, _ = resoudre(ip_res)
        r.nameservers = [ip_res]
    r.lifetime = r.timeout = timeout
    utilises = list(r.nameservers)

    # Une adresse en entrée avec le type PTR : on attend visiblement l'inverse, et exiger la
    # forme « 11.99.2.10.in-addr.arpa » serait une coquetterie.
    question = brut
    if type_ == "PTR":
        try:
            ipaddress.ip_address(brut)
            question = str(dns.reversename.from_address(brut))
        except ValueError:
            pass
    else:
        question = cible_valide(brut)

    t0 = time.time()
    try:
        rep = r.resolve(question, type_)
    except dns.resolver.NXDOMAIN:
        return _dns_vide(brut, question, type_, utilises, t0, "NXDOMAIN",
                         "le nom n'existe pas.")
    except dns.resolver.NoAnswer:
        return _dns_vide(brut, question, type_, utilises, t0, "NOANSWER",
                         "le nom existe, mais n'a pas d'enregistrement %s." % type_)
    except dns.resolver.NoNameservers as e:
        raise SondeError("aucun résolveur n'a répondu (%s)." % str(e)[:160])
    except (dns.exception.Timeout, dns.exception.DNSException) as e:
        raise SondeError("interrogation DNS en échec : %s" % (str(e)[:160] or type(e).__name__))
    return {"name": brut, "query": question, "type": type_,
            "resolvers": utilises, "ms": round((time.time() - t0) * 1000, 3),
            "status": "NOERROR",
            "ttl": rep.rrset.ttl if rep.rrset is not None else None,
            "records": [str(x) for x in rep],
            "answered_by": str(getattr(rep, "nameserver", "") or "") or None}


def _dns_vide(brut, question, type_, resolveurs, t0, statut, detail):
    """Un NXDOMAIN est une RÉPONSE, pas une panne : l'écran doit la montrer comme telle."""
    return {"name": brut, "query": question, "type": type_, "resolvers": resolveurs,
            "ms": round((time.time() - t0) * 1000, 3), "status": statut,
            "detail": detail, "records": [], "ttl": None}


# ─── HTTP ───────────────────────────────────────────────────────────────────
try:
    import requests
except ImportError:
    requests = None

_SCHEMES = ("http://", "https://")


def http(url, method="GET", timeout=5.0, verifier=False, suivre=True):
    """Requête HTTP(S) : code, temps, en-têtes, chaîne de redirections.

    La vérification TLS est désactivée PAR DÉFAUT, comme pour la sonde TLS et pour la même
    raison : les équipements d'un parc portent des certificats auto-signés, et un outil de
    diagnostic qui refuse de leur parler ne diagnostique rien. La sonde TLS, elle, dit
    séparément si la chaîne aurait été acceptée."""
    if requests is None:
        raise SondeError("le module requests n'est pas disponible dans cette image.")
    u = str(url or "").strip()
    if not u:
        raise SondeError("URL attendue.")
    if not u.lower().startswith(_SCHEMES):
        u = "http://" + u
    method = str(method or "GET").upper().strip()
    if method not in ("GET", "HEAD", "OPTIONS"):
        raise SondeError("seules les méthodes de LECTURE sont permises (GET, HEAD, OPTIONS) : "
                         "un outil de test ne doit pas pouvoir modifier ce qu'il observe.")
    timeout = _borne(timeout, 5.0, 0.5, MAX_TIMEOUT, entier=False)
    t0 = time.time()
    try:
        r = requests.request(method, u, timeout=timeout, verify=bool(verifier),
                             allow_redirects=bool(suivre),
                             headers={"User-Agent": "Bobi.Tools/tests-reseau"})
    except requests.exceptions.SSLError as e:
        raise SondeError("échec TLS : %s" % str(e)[:200])
    except requests.exceptions.ConnectTimeout:
        raise SondeError("délai dépassé à la connexion (%.1f s)." % timeout)
    except requests.exceptions.ReadTimeout:
        raise SondeError("connecté, mais aucune réponse avant %.1f s." % timeout)
    except requests.exceptions.RequestException as e:
        raise SondeError("requête impossible : %s" % str(e)[:200])
    ms = round((time.time() - t0) * 1000, 3)
    chaine = [{"status": h.status_code, "url": h.url,
               "location": h.headers.get("Location")} for h in r.history]
    interessants = ("Server", "Content-Type", "Content-Length", "Location", "Set-Cookie",
                    "Strict-Transport-Security", "Cache-Control", "WWW-Authenticate")
    return {"url": u, "final_url": r.url, "method": method,
            "status": r.status_code, "reason": r.reason, "ms": ms,
            "redirects": chaine,
            "headers": {k: r.headers[k] for k in interessants if k in r.headers},
            "size": len(r.content or b""),
            "verified": bool(verifier)}
