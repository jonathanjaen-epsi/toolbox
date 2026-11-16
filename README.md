# NTL-SysToolbox — Diagnostic

Outil CLI Python 3.13 pour diagnostiquer à distance Active Directory, DNS, MySQL/MariaDB et des machines Windows/Linux. Le menu et les commandes exécutent les mêmes contrôles ; aucune modification n'est effectuée sur les cibles.

## Installation

Le dossier `.venv` n'est pas suivi par Git : il doit être recréé après un clonage. Sur Debian, avec Python 3.13 et le paquet système `python3.13-venv` installés, depuis le dossier du projet :

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/ntl-diagnostic --help
```

Si la création échoue parce que `ensurepip` est absent, installer `python3.13-venv` avec le gestionnaire de paquets système, puis relancer ces commandes. Les dépendances sont déclarées dans `pyproject.toml`. Aucun outil ne doit être installé globalement sur les machines diagnostiquées, hormis Python 3 sur la cible Linux.

## Configuration et sécurité

Copier `config.example.json` vers `config.json` et remplacer les noms, adresses et chemins fictifs. Lancer ensuite le CLI depuis le dossier du projet ou utiliser `--config /chemin/config.json`. Le fichier contient :

- `timeout` : délai en secondes, supérieur à 0 et inférieur ou égal à 60, pour chaque opération.
- `ad` : `host` est le nom du contrôleur et `ca_file` le certificat de l'autorité approuvée pour LDAPS. Le service NTDS est lu sur la cible `windows`, dont le nom doit correspondre à `ad.host`.
- `dns` : `server` est l'adresse IP du résolveur interrogé, `name` le nom attendu, `expected_ip` son adresse attendue, et `windows_host` le nom de la machine Windows hébergeant le service DNS. `windows_host` doit correspondre à `windows.host`. Cette correspondance est déclarative : renseigner la machine qui héberge réellement le serveur DNS.
- `mysql` : hôte, port, utilisateur, nom de variable d'environnement contenant le mot de passe, `tls` et chemin de l'autorité de certification si TLS est activé. Le certificat et le nom du serveur sont vérifiés. Pour un laboratoire sans TLS uniquement, définir explicitement `"tls": false, "allow_insecure": true`.
- `windows` : hôte, port WinRM HTTPS, utilisateur, variable contenant le mot de passe, autorité de certification et transport `ntlm` ou `basic`. Le certificat et le nom du serveur sont vérifiés. Le transport `basic` n'est disponible qu'au-dessus d'HTTPS.
- `linux` : hôte, port SSH, utilisateur, fichier de clé privée et fichier `known_hosts`. La clé d'hôte doit déjà y être présente et approuvée. La clé privée doit être utilisable sans phrase secrète ; l'agent SSH n'est pas utilisé.

Ne pas mettre de mots de passe dans le JSON. Pour le mode non interactif, fournir les secrets par des variables d'environnement :

```bash
read -rs -p "Mot de passe WinRM : " NTL_WINRM_PASSWORD; echo
read -rs -p "Mot de passe MySQL : " NTL_MYSQL_PASSWORD; echo
export NTL_WINRM_PASSWORD NTL_MYSQL_PASSWORD
```

Le menu demande les secrets manquants de manière masquée ; ils ne sont conservés que dans l'environnement du processus. Les variables d'environnement peuvent être accessibles à des processus disposant des droits nécessaires : utiliser un compte de service dédié, des permissions restrictives et une solution de gestion de secrets adaptée en production.

## Utilisation

Menu interactif :

```bash
.venv/bin/ntl-diagnostic
```

Le diagnostic global lancé depuis le menu enregistre automatiquement un rapport nommé `rapport-diagnostic-<horodatage UTC>.json` dans le dossier courant et indique son chemin. Avec `--report`, le menu utilise le chemin indiqué.

Diagnostics ciblés, sans menu :

```bash
.venv/bin/ntl-diagnostic --config config.json ad
.venv/bin/ntl-diagnostic --config config.json dns
.venv/bin/ntl-diagnostic --config config.json mysql
.venv/bin/ntl-diagnostic --config config.json windows
.venv/bin/ntl-diagnostic --config config.json linux
.venv/bin/ntl-diagnostic ping 192.0.2.10 --timeout 3
.venv/bin/ntl-diagnostic tcp dc01.example.test 389 --timeout 3
```

Diagnostic global et rapport JSON :

```bash
.venv/bin/ntl-diagnostic --config config.json --format json --report rapport.json global
```

Les options générales précèdent la commande. `--format json` écrit le rapport complet sur la sortie standard ; `--report` écrit également le rapport dans le fichier indiqué, en remplaçant son contenu s'il existe. Une erreur d'écriture est signalée dans la sortie et affecte le statut. Le mode texte par défaut produit une seule ligne compatible avec l'appel d'un plugin de supervision, sans couleurs ; le menu affiche en plus les métriques collectées. Le JSON contient un horodatage UTC, le statut global, le code de sortie et les contrôles avec leurs détails.

| Statut | Code de sortie | Signification |
|---|---:|---|
| OK | 0 | Contrôle réussi |
| WARNING | 1 | Avertissement ; aucun seuil de métrique n'est défini par défaut |
| CRITICAL | 2 | Cible inaccessible ou contrôle ayant échoué |
| UNKNOWN | 3 | Configuration absente/invalide ou contrôle indéterminé |

Le global poursuit les autres contrôles en cas d'échec. La priorité d'agrégation est **CRITICAL > UNKNOWN > WARNING > OK** ; aucun score numérique n'est calculé. `ping` peut être bloqué par un pare-feu même si d'autres services fonctionnent : l'échec ICMP est indiqué séparément et reste CRITICAL.

## Contrôles et prérequis distants

- **AD** : ICMP, ports TCP 389, 636 et 88, lecture anonyme de RootDSE en LDAPS avec certificat vérifié, et état du service NTDS via WinRM. LDAPS est obligatoire ; le port 389 ouvert ne prouve pas qu'une authentification LDAP fonctionne et le port 88 ouvert ne prouve pas qu'une authentification Kerberos fonctionne.
- **DNS** : résolution directe et inverse sur le serveur configuré, comparaison avec le nom et l'adresse attendus, et état du service DNS via WinRM.
- **MySQL/MariaDB** : port TCP, connexion, `SELECT 1` et `SELECT VERSION()`. Un compte disposant du droit de connexion suffit normalement pour ces requêtes ; adapter les restrictions réseau et les droits au serveur.
- **Windows** : version, uptime, charge CPU, mémoire et disques locaux via WinRM HTTPS ; le compte doit pouvoir utiliser PowerShell Remoting, lire les services et interroger CIM.
- **Linux** : distribution, uptime, charge CPU échantillonnée, mémoire disponible et stockage de `/` via SSH ; Python 3 et les fichiers `/proc` doivent être disponibles sur la cible.

Les métriques sont informatives : aucun seuil CPU, mémoire ou disque n'est configuré, donc leur valeur ne provoque pas de WARNING/CRITICAL. Prévoir des règles adaptées à l'environnement avant de les utiliser comme alertes. Les ports réseau et pare-feu doivent être autorisés entre la VM de diagnostic et les cibles ; les certificats doivent correspondre aux noms configurés.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Les tests simulent les services distants et couvrent aussi un port TCP local. Une validation sur les VM réelles reste nécessaire pour confirmer certificats, permissions, pare-feu et compatibilité des services.
