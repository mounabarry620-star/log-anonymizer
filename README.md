# log-anonymizer

Petit outil Python pour **masquer les données sensibles dans des fichiers de logs**
(texte brut ou JSON-lines) à l'aide de règles regex configurables.

## Données détectées par défaut

| Type | Exemple | Jeton |
|------|---------|-------|
| Adresses IPv4 | `192.168.1.42` | `<IPV4>` |
| Adresses IPv6 | `2001:db8::1`, `::1` | `<IPV6>` |
| E-mails | `jean.dupont@example.fr` | `<EMAIL>` |
| Adresses MAC | `00:1A:2B:3C:4D:5E`, `00-1a-...` | `<MAC>` |
| Téléphones FR | `06 12 34 56 78`, `+33 6 12 34 56 78`, `0612345678` | `<PHONE>` |
| Mots de passe / jetons | `password=...`, `token: ...`, `"api_key": "..."`, `Bearer ...` | `<SECRET>` |
| Noms d'utilisateur | `user=alice`, `login: bob`, `Failed password for bob` | `<USER>` |

En JSON, les valeurs des clés sensibles (`password`, `token`, `api_key`, `user`, …)
sont masquées entièrement, et toutes les chaînes sont aussi passées aux règles regex.

## Installation

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"
```

## Utilisation

```bash
# fichier -> stdout
log-anonymizer samples/app.log

# stdin -> fichier
cat samples/app.log | log-anonymizer -o anonymise.log

# JSON-lines (le format est détecté automatiquement ; -f json force le mode strict)
log-anonymizer samples/app.jsonl -f json

# règles personnalisées (YAML ou JSON)
log-anonymizer app.log --rules samples/custom_rules.json

# pseudonymisation cohérente : une même valeur donne toujours le même jeton
log-anonymizer app.log -p --salt "mon-sel-secret"
# ex. 10.0.0.1 -> <IPV4_3f9a1c2b> partout dans le fichier
```

Sans installation : `python -m log_anonymizer ...`.

Options : `input` (défaut stdin), `-o/--output` (défaut stdout), `-r/--rules`,
`-f/--format {auto,text,json}`, `-p/--pseudonymize`, `--salt` (ou variable
d'environnement `LOG_ANONYMIZER_SALT`). Codes retour : `0` OK, `1` erreur
d'entrée, `2` règles invalides.

### Pseudonymisation

Les jetons sont dérivés d'un HMAC-SHA256 (label + valeur, clé = sel), tronqué à
8 caractères hexadécimaux. Utilisez un sel secret : sans sel, une valeur
devinable (une IP par exemple) pourrait être retrouvée par force brute.

## Format des règles

```yaml
sensitive_keys:          # clés JSON masquées entièrement
  - password             # label SECRET par défaut
  - user: USER           # ou label explicite
rules:                   # appliquées dans l'ordre
  - name: commande
    label: ORDER
    pattern: '\bCMD-\d{6}\b'
  - name: secret_kv
    label: SECRET
    flags: [IGNORECASE]
    # le groupe nommé "value" limite le masquage à cette partie
    pattern: '\bpassword\s*=\s*(?P<value>\S+)'
```

Les règles par défaut sont dans `log_anonymizer/default_rules.yaml`.
Un fichier `--rules` **remplace** les règles par défaut (copiez-les pour les étendre).

## Tests

```bash
pytest
```

## Limites

La détection par regex est heuristique : vérifiez toujours un échantillon de la
sortie avant de partager des logs. Les noms d'utilisateur ne sont reconnus que
dans des motifs courants (`user=`, `login:`, `for user ...`).

## Auteur

Mamadou Bailo BARRY — <mounabarry620@gmail.com>
