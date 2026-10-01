# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 BOBI SAS, France
# Auteur : Cyril Mazouer, pour le compte de BOBI SAS
# Distribué sous licence GNU GPL v3 (ou ultérieure) ; voir le fichier LICENSE.

"""
Backend in-process de l'outil « Tests réseau ».

Contrat d'un backend Bobi.Tools (runtime=inprocess) :

    def api(path, method, payload, ctx) -> data | (status, data)

Les sondes elles-mêmes sont dans `netlib.py` ; ce fichier les expose, garde l'historique,
lit les inventaires des autres outils et fait tourner la SURVEILLANCE.

POURQUOI IN-PROCESS — et ce que ça impose
-----------------------------------------
Les tests partent de l'HÔTE : c'est son point de vue sur le réseau qu'on veut, multicast
compris (un conteneur ponté ne voit pas le multicast du LAN). La contrepartie est que tout
tourne dans le processus de l'app, à côté du provider Ember+ du contrôleur. D'où :
  - des sondes bornées en DURÉE (BUDGET_S) et en CONCURRENCE (sémaphores) ;
  - une surveillance bornée (MAX_MONITORS, INTERVAL_MIN_S, pool de MONITOR_WORKERS) et
    limitée aux sondes légères — ni balayage ni multicast planifiés ;
  - un planificateur qui survit au RECHARGEMENT des plugins : `plugins.reload()` ré-exécute
    ce module, et un fil lancé à l'import continuerait de tourner avec l'ancien code. Chaque
    chargement prend donc un jeton ; le fil dont le jeton n'est plus le courant s'arrête.

STOCKAGE (ctx.store, scopé à l'outil)
-------------------------------------
  scope "history"        → un résultat de sonde ponctuelle par ligne (name = horodatage).
  scope "monitor"        → configuration d'un contrôle planifié (name = libellé).
  scope "monitor_state"  → état vivant d'un contrôle (name = id du contrôle), écrit aux
                           TRANSITIONS et au plus une fois par minute : la surveillance ne
                           doit pas transformer la base de l'app en journal à haute fréquence.
"""
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

_ICI = os.path.dirname(os.path.abspath(__file__))
if _ICI not in sys.path:
    sys.path.insert(0, _ICI)
import netlib  # noqa: E402

TYPE = "net_tests"

# ── Bornes ────────────────────────────────────────────────────────────────────
BUDGET_S = 120              # durée PIRE CAS d'une sonde ponctuelle, estimée avant de lancer
HISTORY_MAX = 200           # résultats ponctuels conservés (tous types confondus)
MAX_MONITORS = 50
INTERVAL_MIN_S = 10
INTERVAL_MAX_S = 86400
MONITOR_WORKERS = 4         # contrôles exécutés en parallèle, au plus
POINTS_MAX = 240            # points d'historique gardés par contrôle
FLUSH_S = 60                # écriture de l'état d'un contrôle stable, au plus une fois par minute
DEMARRAGE_S = 15            # délai avant le premier tour (laisse l'app finir de démarrer)

KINDS = ("ping", "traceroute", "tcp", "tls", "http", "dns", "multicast", "scan")
MONITOR_KINDS = ("ping", "tcp", "http", "dns", "tls")

# Concurrence des sondes ponctuelles. Le balayage et le multicast sont exclusifs : deux
# balayages simultanés doublent la charge sans rien apprendre de plus, et deux écoutes
# multicast font livrer deux flux sur la même patte.
_sem_general = threading.BoundedSemaphore(4)
_sem_scan = threading.BoundedSemaphore(1)
_sem_mcast = threading.BoundedSemaphore(1)


class Refus(Exception):
    """Requête refusée avant toute action : (statut HTTP, message)."""
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


# ══════════════════════════════════════════════════════════════════════════════
# Sondes ponctuelles
# ══════════════════════════════════════════════════════════════════════════════

def _num(v, defaut, entier=False):
    try:
        return (int if entier else float)(v)
    except (TypeError, ValueError):
        return defaut


def _ports(v):
    """« 22, 80 443 » ou [22, 80] → [22, 80, 443]."""
    if isinstance(v, (list, tuple)):
        brut = v
    else:
        brut = str(v or "").replace(",", " ").split()
    out = []
    for p in brut:
        n = _num(p, None, entier=True)
        if n is not None:
            out.append(n)
    return out


def _budget(kind, p):
    """Durée pire cas d'une sonde, en secondes. Refuse au-delà de BUDGET_S : une requête HTTP
    qui tient un fil de l'app pendant dix minutes n'est pas un test, c'est une panne."""
    if kind == "ping":
        n = max(1, min(netlib.MAX_COUNT, _num(p.get("count"), 4, True)))
        t = _num(p.get("timeout"), 1.0) + _num(p.get("interval"), 0.25)
        return n * t
    if kind == "traceroute":
        h = max(1, min(netlib.MAX_HOPS, _num(p.get("max_hops"), 20, True)))
        e = max(1, min(5, _num(p.get("tries"), 2, True)))
        return h * e * _num(p.get("timeout"), 1.5)
    if kind == "multicast":
        return _num(p.get("seconds"), 5.0)
    if kind == "scan":
        # Par vague de 64 adresses : un ping, les ports (en parallèle entre eux), le nom inverse.
        import ipaddress
        try:
            n = ipaddress.ip_network(str(p.get("cidr") or "").strip(), strict=False).num_addresses
        except ValueError:
            return 0                                # la lib refusera la plage, avec le motif
        t = _num(p.get("timeout"), 1.0)
        vagues = -(-min(n, netlib.MAX_BALAYAGE) // 64)
        return vagues * (t + (t if _ports(p.get("ports")) else 0) + 1.0)
    # Délai effectif, borné comme le fait la lib. TCP : ports testés en parallèle, un délai.
    # TLS : deux connexions (lecture du certificat, puis validation de la chaîne). HTTP :
    # `requests` applique le délai à la connexion PUIS à la lecture. DNS : un délai.
    defauts = {"tcp": 2.0, "tls": 5.0, "http": 5.0, "dns": 3.0}
    t = min(netlib.MAX_TIMEOUT, max(0.1, _num(p.get("timeout"), defauts.get(kind, 5.0))))
    return t * (2 if kind in ("tls", "http") else 1)


def valider_probe(kind, p):
    """Refus AVANT de lancer quoi que ce soit : type inconnu, réglages trop longs."""
    if kind not in KINDS:
        raise Refus(404, "sonde inconnue : %s" % kind)
    duree = _budget(kind, p or {})
    if duree > BUDGET_S:
        raise Refus(400, "réglages trop longs : jusqu'à %d s dans le pire cas, %d s au plus. "
                         "Réduisez le nombre d'essais ou le délai." % (duree, BUDGET_S))


def run_probe(kind, p, progres=None, arret=None):
    """Exécute une sonde. Lève netlib.SondeError (résultat négatif lisible) ou Refus.
    `progres` / `arret` ne servent qu'aux sondes qui ont des étapes (ping, traceroute, TCP,
    multicast, balayage) ; TLS, HTTP et DNS sont d'un seul tenant."""
    p = p or {}
    valider_probe(kind, p)
    cible = p.get("target")
    if kind == "ping":
        return netlib.ping(cible, count=p.get("count", 4), timeout=p.get("timeout", 1.0),
                           intervalle=p.get("interval", 0.25), charge=p.get("size", 32),
                           progres=progres, arret=arret)
    if kind == "traceroute":
        return netlib.traceroute(cible, max_hops=p.get("max_hops", 20),
                                 timeout=p.get("timeout", 1.5),
                                 essais_par_saut=p.get("tries", 2), progres=progres, arret=arret)
    if kind == "tcp":
        return netlib.tcp(cible, _ports(p.get("ports")), timeout=p.get("timeout", 2.0),
                          progres=progres)
    if kind == "tls":
        return netlib.tls(cible, port=p.get("port", 443), timeout=p.get("timeout", 5.0),
                          sni=(str(p.get("sni") or "").strip() or None))
    if kind == "http":
        return netlib.http(p.get("url") or cible, method=p.get("method", "GET"),
                           timeout=p.get("timeout", 5.0), verifier=bool(p.get("verify")),
                           suivre=p.get("follow", True) is not False)
    if kind == "dns":
        return netlib.dns_query(p.get("name") or cible, type_=p.get("type", "A"),
                                resolveur=(str(p.get("resolver") or "").strip() or None),
                                timeout=p.get("timeout", 3.0))
    if kind == "multicast":
        return netlib.multicast(p.get("group"), p.get("port", 5004),
                                secondes=p.get("seconds", 5.0),
                                interface=(str(p.get("interface") or "").strip() or None),
                                progres=progres, arret=arret)
    if kind == "scan":
        return netlib.balayage(p.get("cidr"), ports=_ports(p.get("ports")),
                               timeout=p.get("timeout", 1.0), progres=progres, arret=arret)
    raise Refus(404, "sonde inconnue : %s" % kind)


def _ms(v):
    return "—" if v is None else ("%.2f ms" % v if v < 10 else "%.0f ms" % v)


def verdict(kind, r, p=None):
    """(ok, résumé d'une ligne) d'un résultat. Sert à l'historique ET à la surveillance :
    un même résultat ne doit pas être « vert » dans un écran et « rouge » dans l'autre."""
    p = p or {}
    if kind == "ping":
        ok = r["received"] > 0
        if not ok:
            return False, "aucune réponse (%d envoyés)" % r["sent"]
        txt = "%d/%d reçus · moy %s" % (r["received"], r["sent"], _ms(r["avg_ms"]))
        if r["loss_pct"]:
            txt += " · %g %% de perte" % r["loss_pct"]
        return True, txt
    if kind == "traceroute":
        n = len(r["hops"])
        return r["reached"], ("atteint en %d saut%s" % (n, "s" if n > 1 else "") if r["reached"]
                              else "non atteint après %d sauts" % n)
    if kind == "tcp":
        ouverts = r["open"]
        etats = ", ".join("%d %s" % (x["port"], {"open": "ouvert", "closed": "refusé",
                                                  "filtered": "filtré"}.get(x["state"], x["state"]))
                          for x in r["ports"])
        return len(ouverts) == len(r["ports"]), etats
    if kind == "tls":
        seuil = _num(p.get("warn_days"), 14, True)
        j = r.get("days_left")
        if j is None:
            return False, "certificat illisible"
        if j < 0:
            return False, "certificat EXPIRÉ depuis %d j" % -j
        txt = "expire dans %d j · %s%s" % (j, r.get("tls_version") or "?",
                                            "" if r.get("verified") else " · chaîne non reconnue")
        return j >= seuil, txt
    if kind == "http":
        attendu = _num(p.get("expect_status"), None, True)
        ok = (r["status"] == attendu) if attendu else r["status"] < 400
        return ok, "%d %s · %s" % (r["status"], r.get("reason") or "", _ms(r["ms"]))
    if kind == "dns":
        if r["status"] != "NOERROR":
            return False, "%s — %s" % (r["status"], r.get("detail") or "")
        attendu = str(p.get("expect") or "").strip()
        recs = r["records"]
        if attendu and not any(attendu in x for x in recs):
            return False, "« %s » absent de la réponse (%s)" % (attendu, ", ".join(recs)[:120])
        return True, "%s · %s" % (", ".join(recs)[:120], _ms(r["ms"]))
    if kind == "multicast":
        if not r["packets"]:
            return False, "aucun paquet en %g s" % r["seconds"]
        return True, "%d paquets · %.1f Mb/s · %d source(s)" % (r["packets"], r["mbps"],
                                                                 len(r["sources"]))
    if kind == "scan":
        return r["alive"] > 0, "%d vivant(s) sur %d" % (r["alive"], r["scanned"])
    return True, ""


def _libelle(kind, p):
    """Ce qui a été testé, en clair, pour la ligne d'historique."""
    if kind == "tcp":
        return "%s : %s" % (p.get("target"), " ".join(str(x) for x in _ports(p.get("ports"))))
    if kind == "tls":
        return "%s:%s" % (p.get("target"), p.get("port", 443))
    if kind == "http":
        return str(p.get("url") or p.get("target") or "")
    if kind == "dns":
        return "%s %s%s" % (p.get("type", "A"), p.get("name") or p.get("target"),
                            (" @" + p["resolver"]) if p.get("resolver") else "")
    if kind == "multicast":
        return "%s:%s" % (p.get("group"), p.get("port", 5004))
    if kind == "scan":
        return str(p.get("cidr") or "")
    return str(p.get("target") or "")


# ── Tâches : un test ponctuel tourne en FOND, et la page relit son avancement ─────────────
# Plutôt qu'une requête qui tient jusqu'à 120 s puis rend tout d'un coup : le POST rend un
# numéro de tâche, la page interroge `jobs/<id>?since=n` et affiche chaque paquet, saut, port ou
# hôte dès qu'il est connu. Interroger plutôt que diffuser (flux HTTP) : rien à craindre d'un
# proxy qui met en tampon, et le test continue — puis rejoint l'historique — si l'opérateur
# change d'onglet ou ferme la page.
JOBS_GARDE_S = 600          # une tâche terminée reste lisible 10 min
JOBS_MAX = 100
EVENTS_MAX = 2000           # étapes conservées par tâche (un /22 peut répondre en masse)


def _jobs():
    rt = _RUNTIME
    if not hasattr(rt, "jobs"):
        rt.jobs, rt.jobs_lock = {}, threading.Lock()
    return rt.jobs, rt.jobs_lock


def _menage(jobs):
    """Appelé sous verrou : oublie les tâches terminées depuis longtemps, puis les plus vieilles."""
    now = time.time()
    for jid in [j for j, x in jobs.items() if x["status"] == "done"
                and now - (x.get("finished_at") or now) > JOBS_GARDE_S]:
        jobs.pop(jid, None)
    finis = sorted((x for x in jobs.values() if x["status"] == "done"), key=lambda x: x["at"])
    while len(jobs) > JOBS_MAX and finis:
        jobs.pop(finis.pop(0)["id"], None)


def _probe(kind, p, ctx):
    try:
        valider_probe(kind, p)
    except Refus as e:
        return e.status, {"error": str(e)}
    sem = _sem_scan if kind == "scan" else _sem_mcast if kind == "multicast" else _sem_general
    if not sem.acquire(blocking=False):
        quoi = {"scan": "un balayage", "multicast": "une écoute multicast"}.get(kind, "4 tests")
        return 429, {"error": "%s déjà en cours — réessayez dans un instant." % quoi}
    user = ctx.user or {}
    job = {"id": uuid.uuid4().hex[:12], "kind": kind, "label": _libelle(kind, p), "params": p,
           "user": user.get("username") or "", "at": time.time(), "status": "running",
           "events": [], "progress": None, "entry": None, "finished_at": None,
           "cancel": threading.Event()}
    jobs, lock = _jobs()
    with lock:
        _menage(jobs)
        jobs[job["id"]] = job

    def progres(evt):
        with lock:
            if evt.get("type") in ("progress", "tick"):
                job["progress"] = evt               # un état, pas une suite : on garde le dernier
            elif len(job["events"]) < EVENTS_MAX:
                job["events"].append(evt)

    threading.Thread(target=_tache, args=(job, p, ctx, sem, progres), daemon=True,
                     name="net_tests-test").start()
    return {"job": job["id"], "kind": kind, "label": job["label"]}


def _tache(job, p, ctx, sem, progres):
    kind = job["kind"]
    try:
        res = run_probe(kind, p, progres=progres, arret=job["cancel"])
        ok, resume = verdict(kind, res, p)
        if res.get("cancelled"):
            resume += " — interrompu"
        erreur = None
    except (netlib.SondeError, Refus) as e:
        res, ok, resume, erreur = None, False, str(e), str(e)
    except Exception as e:                          # noqa: BLE001 — la tâche doit toujours finir
        res, ok, resume, erreur = None, False, "erreur interne : %s" % e, str(e)
    finally:
        sem.release()
    entree = {"kind": kind, "label": job["label"], "params": p, "ok": ok,
              "summary": resume, "error": erreur, "result": res,
              "at": job["at"], "seconds": round(time.time() - job["at"], 2), "user": job["user"]}
    hid = _historiser(ctx, entree)
    jobs, lock = _jobs()
    with lock:
        job["entry"] = {"id": hid, **entree}
        job["status"] = "done"
        job["finished_at"] = time.time()


def _job_vue(job, since=0):
    return {"id": job["id"], "kind": job["kind"], "label": job["label"], "user": job["user"],
            "at": job["at"], "status": job["status"], "progress": job["progress"],
            "cancelling": job["cancel"].is_set() and job["status"] == "running",
            "events": job["events"][since:], "next": len(job["events"]),
            "entry": job["entry"]}


def _historiser(ctx, entree):
    nom = "%014d-%s" % (int(entree["at"] * 1000), entree["kind"])
    try:
        hid = ctx.store.create(nom, entree, scope="history")
    except Exception:                               # noqa: BLE001 — l'historique est un bonus
        return None
    try:
        lignes = ctx.store.list("history")          # triées par name = chronologiques
        for vieux in lignes[:max(0, len(lignes) - HISTORY_MAX)]:
            ctx.store.delete(vieux["id"])
    except Exception:                               # noqa: BLE001
        pass
    return hid


def _history(ctx, kind=None, full=False):
    out = []
    for row in reversed(ctx.store.list("history")):
        v = row.get("value") or {}
        if kind and v.get("kind") != kind:
            continue
        e = {"id": row["id"], **{k: v.get(k) for k in ("kind", "label", "ok", "summary",
                                                        "error", "at", "seconds", "user",
                                                        "params")}}
        if full:
            e["result"] = v.get("result")
        out.append(e)
    return out


# ══════════════════════════════════════════════════════════════════════════════
# Inventaires des autres outils (lecture seule)
# ══════════════════════════════════════════════════════════════════════════════
# Les propriétaires publient dans LEUR volume Docker ; un consommateur conteneurisé le monte
# en lecture seule. In-process, on lit le même fichier directement sur l'hôte. On ne garde
# QUE ce qui sert à désigner une cible : switches.json porte aussi des identifiants de
# connexion, qui n'ont rien à faire dans la réponse de cet outil.

PARK_CONTRACT = 1
_vol_cache = {}


def _volume_dir(volume):
    """Répertoire d'un volume Docker sur l'hôte (mis en cache 5 min), ou None."""
    now = time.time()
    hit = _vol_cache.get(volume)
    if hit and now - hit[0] < 300:
        return hit[1]
    chemin = None
    try:
        p = subprocess.run(["docker", "volume", "inspect", "-f", "{{.Mountpoint}}", volume],
                           capture_output=True, text=True, timeout=5)
        if p.returncode == 0 and p.stdout.strip():
            chemin = p.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    if not chemin:
        chemin = "/var/lib/docker/volumes/%s/_data" % volume
    chemin = chemin if os.path.isdir(chemin) else None
    _vol_cache[volume] = (now, chemin)
    return chemin


def _lire_json(chemin):
    with open(chemin, "r", encoding="utf-8") as f:
        return json.load(f)


def _cibles_switchs():
    src = {"key": "switch_ports", "label": "Switchs", "ok": False, "error": None, "items": []}
    d = _volume_dir("bobitool-switch_ports-data")
    f = os.path.join(d, "switches.json") if d else None
    if not f or not os.path.isfile(f):
        src["error"] = "inventaire introuvable (« Pilotage de switch » absent de cette instance ?)"
        return src
    try:
        brut = _lire_json(f)
    except (OSError, ValueError) as e:
        src["error"] = "inventaire illisible : %s" % e
        return src
    if not isinstance(brut, list):
        src["error"] = "format d'inventaire inattendu"
        return src
    for s in brut:
        if not isinstance(s, dict) or not s.get("host"):
            continue
        lieu = " · ".join(str(x) for x in (s.get("site"), s.get("room"), s.get("rack")) if x)
        src["items"].append({"label": s.get("name") or s["host"], "host": s["host"],
                             "detail": lieu, "tag": "2110" if s.get("is_2110") else ""})
    src["ok"] = True
    src["items"].sort(key=lambda x: x["label"].lower())
    return src


def _cibles_parc():
    src = {"key": "nmos_parc", "label": "Parc NMOS", "ok": False, "error": None, "items": []}
    d = _volume_dir("bobitool-nmos_parc-data")
    f = os.path.join(d, "park.json") if d else None
    if not f or not os.path.isfile(f):
        src["error"] = "park.json absent (« Parc NMOS » absent ou jamais lancé sur cette instance ?)"
        return src
    try:
        brut = _lire_json(f)
    except (OSError, ValueError) as e:
        src["error"] = "park.json illisible : %s" % e
        return src
    # Contrat versionné : un schéma inconnu est REFUSÉ, pas lu au mieux (cf. CLAUDE.md).
    if not isinstance(brut, dict) or brut.get("version") != PARK_CONTRACT:
        src["error"] = ("park.json en version %r, cet outil ne connaît que la %d — à mettre à jour"
                        % (brut.get("version") if isinstance(brut, dict) else None, PARK_CONTRACT))
        return src
    vus = set()
    for e in brut.get("nodes") or []:
        h = e.get("host")
        if not h or h in vus:                       # une machine à plusieurs cages = un hôte
            continue
        vus.add(h)
        src["items"].append({"label": e.get("machine") or e.get("name") or h, "host": h,
                             "detail": e.get("name") if e.get("machine") else "", "tag": ""})
    src["ok"] = True
    src["items"].sort(key=lambda x: x["label"].lower())
    return src


# ══════════════════════════════════════════════════════════════════════════════
# Surveillance
# ══════════════════════════════════════════════════════════════════════════════

def _monitor_value(payload, base=None):
    """Configuration validée d'un contrôle. Lève Refus(400)."""
    v = dict(base or {})
    for k in ("kind", "params", "interval_s", "fail_threshold", "mail", "mail_to", "enabled"):
        if k in payload:
            v[k] = payload[k]
    kind = v.get("kind")
    if kind not in MONITOR_KINDS:
        raise Refus(400, "type de contrôle non planifiable : %s (permis : %s)"
                         % (kind, ", ".join(MONITOR_KINDS)))
    p = v.get("params")
    if not isinstance(p, dict):
        raise Refus(400, "paramètres du contrôle attendus")
    v["interval_s"] = max(INTERVAL_MIN_S, min(INTERVAL_MAX_S, _num(v.get("interval_s"), 60, True)))
    v["fail_threshold"] = max(1, min(20, _num(v.get("fail_threshold"), 3, True)))
    v["mail"] = bool(v.get("mail"))
    v["mail_to"] = str(v.get("mail_to") or "").strip()
    v["enabled"] = v.get("enabled", True) is not False
    # Un contrôle planifié ne doit pas pouvoir tenir un fil longtemps : budget réduit.
    duree = _budget(kind, p)
    if duree > 30:
        raise Refus(400, "un contrôle planifié doit tenir en 30 s au pire (ici %d s)." % duree)
    if v["interval_s"] < duree:
        raise Refus(400, "l'intervalle (%d s) est plus court que la durée du test (%d s)."
                         % (v["interval_s"], duree))
    if kind == "http":
        if not str(p.get("url") or "").strip():
            raise Refus(400, "URL attendue.")
    else:
        try:
            netlib.cible_valide(p.get("name") if kind == "dns" else p.get("target"))
        except netlib.SondeError as e:
            raise Refus(400, str(e))
    return v


class _Etat:
    """État vivant des contrôles, en mémoire, partagé entre le planificateur et l'API."""
    def __init__(self):
        self.lock = threading.Lock()
        self.d = {}                                 # id → état
        self.charge = False

    def get(self, mid):
        with self.lock:
            return dict(self.d.get(mid) or {})


def _etat_neuf():
    return {"status": "unknown", "since": None, "last_run": None, "last_ok": None,
            "last_summary": None, "last_error": None, "failures": 0, "points": [],
            "_flushed": 0}


def _charger_etats(store):
    if ETAT.charge:
        return
    with ETAT.lock:
        if ETAT.charge:
            return
        for row in store.list("monitor_state"):
            try:
                ETAT.d[int(row["name"])] = {**_etat_neuf(), **(row.get("value") or {}),
                                            "_row": row["id"], "_flushed": time.time()}
            except (TypeError, ValueError):
                continue
        ETAT.charge = True


def _persister(store, mid, e):
    v = {k: x for k, x in e.items() if not k.startswith("_")}
    try:
        if e.get("_row") and store.get(e["_row"]):
            store.update(e["_row"], value=v)
        else:
            e["_row"] = store.create(str(mid), v, scope="monitor_state")
        e["_flushed"] = time.time()
    except Exception:                               # noqa: BLE001
        pass


def _executer(mid, cfg, ctx, manuel=False):
    """Un passage d'un contrôle : sonde, verdict, transition, alerte."""
    t0 = time.time()
    try:
        res = run_probe(cfg["kind"], cfg["params"])
        ok, resume = verdict(cfg["kind"], res, cfg["params"])
        err = None
        ms = res.get("avg_ms") or res.get("ms")
        if cfg["kind"] == "tcp":
            ms = next((x.get("ms") for x in res["ports"] if x.get("ms")), None)
    except (netlib.SondeError, Refus) as e:
        ok, resume, err, ms = False, str(e), str(e), None
    except Exception as e:                          # noqa: BLE001 — un contrôle ne tue pas le fil
        ok, resume, err, ms = False, "erreur interne : %s" % e, str(e), None

    with ETAT.lock:
        e = ETAT.d.setdefault(mid, _etat_neuf())
        avant = e["status"]
        e["last_run"] = t0
        e["last_summary"] = resume
        e["last_error"] = err
        e["points"] = (e["points"] + [{"t": round(t0), "ok": ok, "ms": ms}])[-POINTS_MAX:]
        if ok:
            e["failures"] = 0
            e["last_ok"] = t0
            apres = "up"
        else:
            e["failures"] += 1
            # Un échec isolé n'est pas une panne : on attend `fail_threshold` échecs
            # consécutifs ; d'ici là, l'état précédent tient.
            apres = "down" if e["failures"] >= cfg["fail_threshold"] else avant
        transition = apres != avant
        if transition:
            e["status"] = apres
            e["since"] = t0
        a_ecrire = transition or time.time() - e.get("_flushed", 0) > FLUSH_S
        copie = dict(e)
    if a_ecrire:
        with ETAT.lock:
            _persister(ctx.store, mid, ETAT.d[mid])
    if transition and avant != "unknown":
        _alerter(cfg, apres, resume, ctx, copie)
    return copie


def _alerter(cfg, statut, resume, ctx, e):
    nom = cfg.get("_name") or "contrôle"
    if statut == "down":
        action, sujet = "monitor_down", "[Tests réseau] EN ÉCHEC : %s" % nom
        corps = ("Le contrôle « %s » est en échec depuis %d passage(s) consécutif(s).\n\n"
                 "Dernier résultat : %s\n" % (nom, e.get("failures") or 0, resume))
    else:
        action, sujet = "monitor_up", "[Tests réseau] rétabli : %s" % nom
        corps = "Le contrôle « %s » est de nouveau en succès.\n\nDernier résultat : %s\n" % (nom, resume)
    try:
        ctx.audit(action, "%s — %s" % (nom, resume))
    except Exception:                               # noqa: BLE001
        pass
    if cfg.get("mail"):
        try:
            ctx.send_mail(sujet, corps, to=cfg.get("mail_to") or None)
        except Exception:                           # noqa: BLE001
            pass


def _ctx_systeme():
    from app import tools as _tools                 # résolution paresseuse : on est dans l'app
    return _tools._system_ctx(TYPE, "Tests réseau (surveillance)")


def _monitors(store):
    out = []
    for row in store.list("monitor"):
        v = dict(row.get("value") or {})
        v["_name"] = row["name"]
        out.append((row["id"], v))
    return out


def _actif_dans_app():
    """Vrai seulement dans l'app web, outil présent et non désactivé. Le registre des plugins
    est aussi chargé par des outils en ligne de commande (distribution, mise à jour) : ils ne
    doivent ni sonder le réseau ni envoyer d'alertes."""
    if "app.routes" not in sys.modules:
        return False
    pl = sys.modules.get("app.plugins")
    if not pl or not pl.get(TYPE):
        return False
    try:
        return not pl.is_disabled(TYPE)
    except Exception:                               # noqa: BLE001
        return True


def _planificateur(jeton, stop):
    if stop.wait(DEMARRAGE_S):
        return
    if "app.routes" not in sys.modules:
        return          # outil en ligne de commande : jamais de sonde ni d'alerte d'ici
    pool = ThreadPoolExecutor(max_workers=MONITOR_WORKERS, thread_name_prefix="net_tests-mon")
    en_cours = set()
    lock = threading.Lock()
    ctx = None
    try:
        while not stop.is_set() and _RUNTIME.jeton == jeton:
            if _actif_dans_app():
                try:
                    ctx = ctx or _ctx_systeme()
                    _charger_etats(ctx.store)
                    maintenant = time.time()
                    for mid, cfg in _monitors(ctx.store):
                        if not cfg.get("enabled", True) or cfg.get("kind") not in MONITOR_KINDS:
                            continue
                        e = ETAT.get(mid)
                        if maintenant - (e.get("last_run") or 0) < cfg.get("interval_s", 60):
                            continue
                        with lock:
                            if mid in en_cours:
                                continue
                            en_cours.add(mid)

                        def tache(mid=mid, cfg=cfg):
                            try:
                                _executer(mid, cfg, ctx)
                            finally:
                                with lock:
                                    en_cours.discard(mid)
                        pool.submit(tache)
                except Exception:                   # noqa: BLE001 — le planificateur ne meurt pas
                    pass
            stop.wait(1.0)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


class _Runtime:
    jeton = None
    stop = None


# Un seul planificateur par PROCESSUS, quel que soit le nombre de rechargements du module :
# l'objet d'exécution est rangé dans sys.modules, qui, lui, survit au rechargement.
_RUNTIME = sys.modules.setdefault("_bt_net_tests_runtime", _Runtime())
ETAT = getattr(_RUNTIME, "etat", None) or _Etat()
_RUNTIME.etat = ETAT


def _demarrer():
    if _RUNTIME.stop is not None:
        _RUNTIME.stop.set()                         # arrête le planificateur du code précédent
    jeton, stop = uuid.uuid4().hex, threading.Event()
    _RUNTIME.jeton, _RUNTIME.stop = jeton, stop
    threading.Thread(target=_planificateur, args=(jeton, stop), daemon=True,
                     name="net_tests-planificateur").start()


_demarrer()


def _monitor_vue(mid, row_name, cfg):
    e = ETAT.get(mid)
    return {"id": mid, "name": row_name,
            **{k: cfg.get(k) for k in ("kind", "params", "interval_s", "fail_threshold",
                                       "mail", "mail_to", "enabled")},
            "label": _libelle(cfg.get("kind"), cfg.get("params") or {}),
            "state": {k: x for k, x in e.items() if not k.startswith("_") and k != "points"}
                     or {"status": "unknown"},
            "points": e.get("points") or []}


# ══════════════════════════════════════════════════════════════════════════════
# API
# ══════════════════════════════════════════════════════════════════════════════

def api(path, method, payload, ctx):
    parts = [p for p in (path or "").split("/") if p]
    payload = payload or {}
    try:
        return _api(parts, method, payload, ctx)
    except Refus as e:
        return e.status, {"error": str(e)}


def _api(parts, method, payload, ctx):
    if parts == ["info"] and method == "GET":
        try:
            ifs = netlib.interfaces()
        except Exception:                           # noqa: BLE001
            ifs = []
        return {"kinds": list(KINDS), "monitor_kinds": list(MONITOR_KINDS),
                "interfaces": ifs, "dns_types": netlib.TYPES_DNS,
                "dns_available": netlib.dns is not None,
                "limits": {"budget_s": BUDGET_S, "max_count": netlib.MAX_COUNT,
                           "max_hops": netlib.MAX_HOPS, "max_ports": netlib.MAX_PORTS,
                           "max_scan": netlib.MAX_BALAYAGE, "max_listen_s": netlib.MAX_ECOUTE,
                           "max_monitors": MAX_MONITORS, "interval_min_s": INTERVAL_MIN_S},
                "inprocess": True}

    if parts == ["targets"] and method == "GET":
        return {"sources": [_cibles_switchs(), _cibles_parc()]}

    if len(parts) == 2 and parts[0] == "probe" and method == "POST":
        return _probe(parts[1], payload, ctx)

    if parts == ["jobs"] and method == "GET":
        jobs, lock = _jobs()
        with lock:
            return {"jobs": [_job_vue(j, since=len(j["events"])) for j in jobs.values()
                             if j["status"] == "running"]}
    if len(parts) >= 2 and parts[0] == "jobs":
        jobs, lock = _jobs()
        with lock:
            job = jobs.get(parts[1])
            if not job:
                return 404, {"error": "tâche inconnue ou expirée — le résultat est dans l'historique"}
            if len(parts) == 2 and method == "GET":
                return _job_vue(job, since=max(0, _num(payload.get("since"), 0, True)))
        if len(parts) == 3 and parts[2] == "cancel" and method == "POST":
            u = ctx.user or {}
            if job["user"] != (u.get("username") or "") and u.get("role") != "admin":
                return 403, {"error": "seul l'auteur du test (ou un administrateur) peut l'arrêter"}
            job["cancel"].set()
            return {"ok": True}

    if parts == ["history"]:
        if method == "GET":
            return {"history": _history(ctx, kind=payload.get("kind") or None)}
        if method == "DELETE":
            n = 0
            for row in ctx.store.list("history"):
                ctx.store.delete(row["id"])
                n += 1
            ctx.audit("history_clear", "%d résultat(s)" % n)
            return {"deleted": n}
    if len(parts) == 2 and parts[0] == "history":
        hid = _num(parts[1], None, True)
        row = ctx.store.get(hid) if hid is not None else None
        if not row or row.get("scope") != "history":
            return 404, {"error": "résultat introuvable"}
        if method == "GET":
            return {"id": row["id"], **(row.get("value") or {})}
        if method == "DELETE":
            ctx.store.delete(row["id"])
            return {"ok": True}

    if parts == ["monitors"]:
        if method == "GET":
            _charger_etats(ctx.store)
            return {"monitors": [_monitor_vue(mid, cfg["_name"], cfg)
                                 for mid, cfg in _monitors(ctx.store)],
                    "running": _RUNTIME.jeton is not None}
        if method == "POST":
            nom = str(payload.get("name") or "").strip()
            if not nom:
                return 400, {"error": "nom du contrôle requis"}
            if len(ctx.store.list("monitor")) >= MAX_MONITORS:
                return 400, {"error": "%d contrôles au plus." % MAX_MONITORS}
            v = _monitor_value(payload)
            mid = ctx.store.create(nom, v, scope="monitor")
            ctx.audit("monitor_create", "%s (%s %s)" % (nom, v["kind"], _libelle(v["kind"], v["params"])))
            return {"id": mid}

    if len(parts) >= 2 and parts[0] == "monitors":
        mid = _num(parts[1], None, True)
        row = ctx.store.get(mid) if mid is not None else None
        if not row or row.get("scope") != "monitor":
            return 404, {"error": "contrôle introuvable"}
        cfg = {**(row.get("value") or {}), "_name": row["name"]}
        if len(parts) == 3 and parts[2] == "run" and method == "POST":
            _charger_etats(ctx.store)
            _executer(mid, cfg, ctx, manuel=True)
            return _monitor_vue(mid, row["name"], cfg)
        if len(parts) == 2:
            if method == "GET":
                _charger_etats(ctx.store)
                return _monitor_vue(mid, row["name"], cfg)
            if method == "PUT":
                nom = str(payload.get("name") or row["name"]).strip()
                v = _monitor_value(payload, base=row.get("value") or {})
                ctx.store.update(mid, name=nom, value=v)
                if (row.get("value") or {}).get("params") != v["params"] or \
                        (row.get("value") or {}).get("kind") != v["kind"]:
                    with ETAT.lock:                 # autre test : l'historique ne vaut plus
                        vieux = ETAT.d.pop(mid, None)
                    if vieux and vieux.get("_row"):
                        ctx.store.delete(vieux["_row"])
                ctx.audit("monitor_update", nom)
                return {"ok": True}
            if method == "DELETE":
                ctx.store.delete(mid)
                with ETAT.lock:
                    vieux = ETAT.d.pop(mid, None)
                if vieux and vieux.get("_row"):
                    ctx.store.delete(vieux["_row"])
                ctx.audit("monitor_delete", row["name"])
                return {"ok": True}

    return 404, {"error": "route inconnue : %s %s" % (method, "/".join(parts))}
