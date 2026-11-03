# Domain Pulse

Audit rapide d'un nom de domaine : DNS, adresses IP, identité du serveur,
certificat TLS, temps de réponse, sous-domaines, scan de ports et export PDF.

## Fonctionnalités

- **Tous les enregistrements DNS publics** : `A`, `AAAA`, `CNAME`, `MX`, `NS`,
  `TXT`, `SOA`, `CAA`, `SRV`, `HTTPS` et `DMARC`.
- **Adresses IP** IPv4 et IPv6, avec **DNS inverse** (PTR).
- **Identité du serveur** : en-tête HTTP `Server`, IP principale, nom PTR.
- **Temps de réponse** : résolution DNS, requête HTTP et durée totale.
- **Certificat TLS** : sujet, émetteur, expiration, jours restants, protocole,
  chiffrement et noms alternatifs (SAN).
- **Sous-domaines** : certificat TLS + journaux de certificats (crt.sh) +
  vérification de préfixes courants (`www`, `api`, `mail`, `dev`, ...).
- **Disponibilité fiable** : essai HTTPS, puis HTTPS sans vérification du
  certificat (si le certificat est invalide), puis HTTP. Toute réponse HTTP
  (même `403` ou `404`) est considérée comme « joignable ».
- **Scan de ports TCP** : ports courants ou plage personnalisée, détection des
  ports ouverts, nom du service et latence.
- **Export PDF** pour l'audit de domaine et pour le scan de ports.
- Cache mémoire de 5 minutes et protection contre les cibles non publiques.

## Endpoints

| Méthode | Route | Description |
| --- | --- | --- |
| `GET` | `/` | Interface web |
| `GET` | `/health` | Sonde de disponibilité |
| `GET` | `/check?domain=example.com` | Audit complet en JSON |
| `GET` | `/report.pdf?domain=example.com` | Rapport PDF de l'audit |
| `GET` | `/scan?target=1.2.3.4` | Scan TCP des ports |
| `GET` | `/scan/report.pdf?target=1.2.3.4` | Rapport PDF du scan |

Options communes :

- `refresh=true` : ignore le cache de 5 minutes.
- `DNS_RESOLVERS` (variable d'environnement) : liste de résolveurs DNS séparés
  par des virgules. Par défaut : `1.1.1.1,8.8.8.8,9.9.9.9`. Le résolveur
  système est utilisé en secours.
- `ALLOW_PRIVATE_SCAN=1` (variable d'environnement) : autorise le scan
  d'adresses privées (`192.168.x.x`, `10.x.x.x`, `127.0.0.1`, ...).
  Désactivé par défaut.

Options du scan :

- `target` : adresse IP ou nom de domaine (le domaine est résolu en IPv4/IPv6).
- `ports` : `22,80,443`, `8000-8100`, ou vide pour les ports courants.
  Maximum **1024 ports** par scan.
- `timeout` : délai de connexion par port, entre `0.2` et `2.0` secondes
  (défaut `1.0`).

```bash
# Audit JSON
curl "http://localhost:8000/check?domain=example.com"

# Rapport PDF d'audit
curl -OJ "http://localhost:8000/report.pdf?domain=example.com"

# Scan des ports 22, 80 et 443
curl "http://localhost:8000/scan?target=example.com&ports=22,80,443"

# Scan des ports 1 à 1024
curl "http://localhost:8000/scan?target=1.2.3.4&ports=1-1024"

# Rapport PDF du scan
curl -OJ "http://localhost:8000/scan/report.pdf?target=1.2.3.4&ports=22,80,443"
```

## Lancer le projet

```bash
uv sync
uv run uvicorn main:app --reload
```

L'application écoute sur <http://localhost:8000>.

## Tests et qualité

```bash
uv run python -m pytest -v
```

La CI GitHub Actions est dans `.github/workflows/ci.yaml` (tests puis build et
publication de l'image Docker).

## Docker

```bash
docker build -t domain-pulse .
docker run --rm -p 8000:8000 domain-pulse
```

L'image tourne avec un utilisateur non privilégié et expose un `HEALTHCHECK`
sur `/health`.

## Notes

- Les sous-domaines dépendent de sources externes (crt.sh) : en cas
  d'indisponibilité, l'outil se rabat sur le certificat TLS et des préfixes
  courants.
- Les domaines privés (`localhost`, `.local`, `.internal`) et les adresses IP
  littérales sont refusés par l'audit de domaine ; une requête HTTP est bloquée
  si le domaine ne résout que vers des adresses non publiques. Le scan accepte
  une IP littérale, mais bloque les adresses privées sauf avec
  `ALLOW_PRIVATE_SCAN=1`.
- Le scan de ports est **TCP uniquement**. Un port filtré par un pare-feu peut
  apparaître comme fermé, et certains services ne répondent pas au simple
  établissement de connexion.
- N'utilisez le scan que sur des cibles que vous êtes autorisé à tester.
- La vérification de disponibilité accepte toute réponse HTTP, même `403` ou
  `404` : `reachable` indique que le serveur répond, `status_ok` indique un code
  `200-399`.
- Le résultat est mis en cache 5 minutes pour éviter de solliciter les sources
  externes à chaque appel.
