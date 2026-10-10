# Tests réseau — plugin Bobi.Tools

Diagnostic réseau **depuis le serveur** [Bobi.Tools](https://github.com/bob-integration/bobitools) :
le chemin mesuré est celui du serveur vers la cible, pas celui du poste de l'utilisateur. Les
résultats sont structurés (chaque paquet, chaque saut, chaque port), jamais du texte à relire.

## Ce que fait l'outil

- **Tests ponctuels** : ping (perte, gigue), traceroute, ports TCP (refusé ou filtré), certificat
  TLS (jours restants, chaîne valide ou non), HTTP en lecture seule, DNS avec résolveur au choix.
- **Écoute multicast** (comptage des paquets, débit, sources) et **balayage** d'une plage
  jusqu'à un /22.
- **Résultats au fil de l'eau**, test interruptible ; il tourne sur le serveur et continue si la
  page est fermée.
- **Cibles proposées** depuis les inventaires de
  [Pilotage de switch](https://github.com/bob-integration/bobitools-plugin-switch_ports) et de
  [Parc NMOS](https://github.com/bob-integration/bobitools-plugin-nmos_parc), s'ils sont installés.
- **Surveillance planifiée** (ping, TCP, HTTP, DNS, TLS) avec seuil d'échecs consécutifs, journal
  et alerte par e-mail via le service
  [mail](https://github.com/bob-integration/bobitools-service-mail).
- **Historique** partagé des 200 derniers tests.

## À savoir

- L'écoute multicast envoie un **IGMP join** réel : le switch livre le flux au serveur, plusieurs
  Gb/s pour une vidéo ST 2110. Choisir l'interface du fabric et une durée courte. L'écoute est en
  ASM : sur un réseau SSM seul, rien n'arrive.
- Chaque test est borné à 120 s dans le pire cas ; au-delà, il est refusé avant de partir.

## Prérequis

- Aucun Docker : l'outil tourne dans Bobi.Tools (`runtime: inprocess`).
- Ping, traceroute et balayage exigent des sockets ICMP brutes : Bobi.Tools doit tourner en root,
  ou avec la capacité `CAP_NET_RAW`.
- Dépendance Python : `dnspython` (sonde DNS), déclarée dans le `requirements.txt` du cœur.

## Installation

Dans Bobi.Tools : **Réglages → Outils → Catalogue**, bouton « Installer ». Ou, sur une machine
neuve, en une ligne :

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/bob-integration/bobitools/main/get.sh) --outils net_tests
```

L'aide complète est dans [`help.md`](help.md), affichée dans Bobi.Tools (menu « ? » → Aide).

## Sécurité

- Les requêtes partent du serveur : l'outil voit ce que le serveur voit. Aucune commande système
  n'est lancée pour les tests ; les sondes parlent directement ICMP, TCP, TLS, HTTP et DNS.
- Le balayage d'une plage et l'écoute multicast sont réservés aux administrateurs par défaut
  (permissions ajustables dans les rôles).

## Pour les développeurs

- `netlib.py` : les sondes, sans couche HTTP ; chaque fonction rend une structure.
- `backend.py` : API de l'outil, historique, lecture des inventaires, planificateur.
- `page.html` / `page.js` / `page.css` : l'interface.
- `help.md` : l'aide utilisateur ; `meta.json` : le journal des versions.

## In English

Network diagnostics run from the Bobi.Tools server itself: ping, traceroute, TCP ports, TLS
certificate, HTTP, DNS (choice of resolver), multicast listening and range scanning, with
structured live results, a shared history, and scheduled monitoring with e-mail alerts. Targets
can be picked from the switch and NMOS inventories. Runs in-process; ICMP tests need root or
`CAP_NET_RAW`, and the DNS probe needs `dnspython`.

## Licence

GPL-3.0-or-later — © 2026 BOBI SAS. Voir [LICENSE](LICENSE).
