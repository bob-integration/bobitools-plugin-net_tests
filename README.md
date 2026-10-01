# Tests réseau — plugin Bobi.Tools

Diagnostic réseau depuis le serveur Bobi.Tools : ping, traceroute, ports TCP, certificat TLS,
HTTP, DNS, écoute multicast, balayage de plage ; historique partagé et surveillance planifiée
avec alerte. Runtime **in-process** (`backend.py`) : les tests partent de l'hôte.

- `netlib.py` — les sondes, sans couche HTTP ; chaque fonction rend une structure.
- `backend.py` — API de l'outil, historique, lecture des inventaires, planificateur.
- `page.html` / `page.js` / `page.css` — l'interface.
- `help.md` — l'aide utilisateur ; `meta.json` — le journal des versions.

Dépendance Python : `dnspython` (sonde DNS), déclarée dans le `requirements.txt` du cœur.
Ping, traceroute et balayage exigent des sockets ICMP brutes : l'app doit tourner en root
(ou avec la capacité `CAP_NET_RAW`).

Licence GPL-3.0-or-later — © 2026 BOBI SAS.
