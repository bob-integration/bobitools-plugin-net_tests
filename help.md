# Tests réseau

Diagnostic réseau **depuis le serveur Bobi.Tools lui-même**. Le chemin mesuré est celui du
serveur vers la cible, pas celui de votre poste : « ça répond de chez moi mais pas du serveur »
se tranche ici.

Les résultats sont **structurés** (chaque paquet, chaque saut, chaque port), jamais du texte de
commande à relire. Aucune commande système n'est lancée : les sondes parlent directement ICMP,
TCP, TLS, HTTP et DNS, et rien de ce que vous saisissez n'atteint un interpréteur.

## Tester

Choisissez le type de test, remplissez la cible, **Lancer**. Le champ cible propose les
équipements connus des inventaires **Pilotage de switch** et **Parc NMOS** (s'ils sont installés
sur cette instance) ; la saisie libre reste toujours possible.

| Test | Ce qu'il dit |
|---|---|
| **Ping** | Chaque paquet, perte, min / moyenne / max et **gigue**. Une moyenne basse qui oscille n'a pas le même sens qu'une moyenne basse stable. |
| **Traceroute** | Le chemin, saut par saut (ICMP à TTL croissant). Un saut muet « * » n'est **pas** une panne : beaucoup de routeurs ne répondent pas. |
| **Ports TCP** | Distingue **refusé** (l'hôte répond, rien n'écoute : service arrêté) de **filtré** (aucune réponse : pare-feu, ou hôte absent). 64 ports au plus. |
| **Certificat TLS** | Émetteur, noms couverts, **jours restants**, et séparément : la chaîne serait-elle acceptée par un navigateur ? Les certificats auto-signés sont lus quand même. |
| **HTTP** | Code, temps, redirections, en-têtes utiles. Lecture seule : GET, HEAD, OPTIONS. |
| **DNS** | Enregistrements, temps de réponse, **résolveur au choix** (comparer deux résolveurs sur la même question). Une IP avec le type PTR fait la résolution inverse. NXDOMAIN est une réponse, affichée comme telle. |
| **Multicast** | Rejoint un groupe et compte paquets, débit et sources. |
| **Balayage** | Qui répond sur une plage (jusqu'à un /22) : ping, plus 8 ports au plus. Un port ouvert suffit à déclarer l'hôte vivant, même muet au ping. |

Chaque test est borné : au-delà de **120 s dans le pire cas** (nombre d'essais × délai), il est
refusé avant de partir, avec le calcul.

### ⚠ Multicast : rejoindre n'est pas observer

L'écoute envoie un **IGMP join** réel : le switch livre alors le flux au serveur pendant toute
l'écoute. Une essence vidéo ST 2110 pèse **plusieurs Gb/s** — de quoi saturer une interface
d'administration. Choisissez l'interface **du fabric** (sur un serveur à plusieurs pattes, « par
défaut » est celle de la route par défaut, rarement le fabric) et gardez une durée courte.
L'écoute est en ASM (any-source) : sur un réseau qui n'accepte que le SSM, rien n'arrivera.

## Surveillance

Un **contrôle** est un test exécuté par le serveur à intervalle régulier, même quand personne
ne regarde. Créez-le avec **Nouveau contrôle**, ou depuis le résultat d'un test avec
**Surveiller ce test** (les réglages sont repris).

- Types planifiables : ping, ports TCP, HTTP, DNS, certificat TLS. Ni balayage ni multicast :
  ils sont trop lourds pour tourner en boucle.
- **Intervalle** : 10 s au minimum, et jamais plus court que la durée du test lui-même.
- **Alerter après N échecs** : un échec isolé n'est pas une panne. Le contrôle passe « EN
  ÉCHEC » au N-ième échec consécutif, et revient « en succès » au premier succès.
- Critères d'échec : ping sans aucune réponse ; un port demandé non ouvert ; code HTTP ≥ 400
  (ou différent du **code attendu**) ; DNS sans réponse ou sans la **réponse attendue** ;
  certificat expirant sous le seuil en jours.
- **Alerte** : chaque passage en échec et chaque retour est inscrit au **journal** de l'outil.
  Cochez **Prévenir par e-mail** pour recevoir aussi un mail (service *mail* requis) ; sans
  destinataire, ce sont ceux par défaut du service mail.
- Le premier verdict d'un contrôle neuf n'envoie pas d'alerte : il n'y a pas encore de
  « changement ».
- La **tendance** montre les derniers passages (vert / rouge) ; survolez pour l'heure et le temps.

## Historique

Les 200 derniers tests ponctuels, de tous les utilisateurs, avec qui les a lancés. Un clic
déplie le résultat complet. Utile pour comparer « avant / après » une intervention.

## Droits

| Permission | Par défaut |
|---|---|
| Lancer ping, traceroute, TCP, TLS, HTTP, DNS | tout compte ayant l'usage des outils |
| **Balayer une plage** | administrateurs seulement |
| **Écouter un groupe multicast** | administrateurs seulement |
| Gérer la surveillance | opérateurs |
| Vider l'historique | opérateurs |

Modifiables dans **Réglages → Utilisateurs → rôles**.
