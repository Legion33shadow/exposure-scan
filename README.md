# exposure-scan

**Question posée :** pour chaque appel d'outil MCP passé par mes agents (Cursor, Claude Code), quelle version
*signée* de l'outil était en service à ce moment-là ?

Vous lancez l'outil chez vous, hors ligne, sans compte, sur vos propres dossiers Cursor et Claude Code. Il produit un
dossier vérifiable : chaque appel y est classé par rapport à un historique externe signé des définitions d'outils
(le « journal »). Ce journal publie aussi ses trous d'observation.

## Trust & status

Trust & status. Verifies offline against the LEGION MCP transparency log, signed with a pinned Ed25519 key — verify the pinned key and this release’s SHA-256 out-of-band. An independent witness cosignature is pending (not yet witnessed). A tool-definition match to a signed entry means the presented definition equals a signed fingerprint — it does not prove the tool was executed or had any effect. Local client transcripts/caches are unsigned.

v0.1.1 ships a demo bundle (`legion-log-demo-34964`, about 2 MB, inclusion-proof mode): 4 servers, every leaf signed and proven by an RFC 6962 path against the signed tree head 34964, so the tool runs offline out of the box. Calls to servers outside the demo stay UNKNOWN. The full signed-log snapshot (156 MB, SHA-256 14d50a88394dc9a265fa4a41123da781cdb03cdf72753cfc9cfbc5fc2d898409) is not attached (upload bandwidth); available on request.

## Ce que l'outil lit, et ce qu'il ne fait jamais

- **Il lit, en lecture seule, uniquement :**
  - l'heure de chaque appel ;
  - le client (cursor / claude-code) ;
  - le nom du serveur côté client ;
  - le nom de l'outil ;
  - l'empreinte SHA-256 des définitions d'outils présentées à votre client ;
  - le `--server-id` déclaré dans votre configuration MCP.
- **Il ne copie jamais :** arguments, réponses, prompts, messages, descriptions d'outils. Un test le vérifie avec des
  valeurs témoins : 0 trouvée.
- **Il n'envoie rien.** Aucun réseau. Vous pouvez le lancer sous `unshare -rn` (Linux), qui coupe le réseau.
- **Il ne modifie rien** dans vos dossiers. Il écrit seulement le dossier `--out`, qui ne doit pas exister.

## Installer

Prérequis : Python ≥ 3.9 et le paquet `cryptography` (vérification Ed25519). Aucune autre dépendance.

```sh
tar xzf exposure-scan-cli-0.1.1.tar.gz
tar xzf legion-log-demo-34964.tar.gz
sha256sum -c SHA256SUMS            # à comparer avec les empreintes obtenues par un autre canal
cd exposure-scan-cli-0.1.1
unshare -rn sh VERIFY_BUNDLE.sh ../legion-log-demo-34964      # contrôle complet du bundle, hors ligne
```

## Bundle de démonstration (mode preuve d'inclusion)

`legion-log-demo-34964` est un sous-ensemble du journal signé : toutes les feuilles de 4 serveurs
(`com.dexpaprika/dexpaprika`, `com.remoshift/jobs`, `com.swarmmemo/bulletin`, `dk.afbudsrejser/travel-search`), la tête
signée 34964, le checkpoint C2SP, la couverture signée (tête, index, cycles) et les seules tranches de ces serveurs.
Son `BUNDLE_MANIFEST.json` porte `"mode": "inclusion"` et la liste `servers`. Le contrôle vérifie :

- la signature de la tête et la clé racine épinglée ;
- chaque feuille : signature Ed25519 et chemin d'inclusion RFC 6962 (`tlog/proofs/INC-<i>.json`) jusqu'à la racine signée ;
- la complétude par serveur : chaîne `prev_leaf_index` sans trou, et chaque empreinte OBSERVED de la couverture signée
  égale à une feuille du bundle ;
- les cycles et les tranches de couverture des serveurs déclarés.

Le bundle complet (mode historique, racine recalculée sur toutes les feuilles) reste accepté tel quel.

## Lancer sur vos propres dossiers

```sh
cd exposure-scan-cli-0.1.1
unshare -rn sh exposure-scan.sh \
  --client-dir ~/.claude --client-dir ~/.claude.json \
  --client-dir ~/.cursor --client-dir ~/.config/Cursor \
  --log-bundle ../legion-log-demo-34964 --out ~/mon-dossier-exposure
```

- `sh exposure-scan.sh` lance `python3 -I` (isolé). Équivalent non isolé, depuis ce dossier : `python3 -m exposure_scan ...`.
- Passez seulement les dossiers que vous voulez faire lire. Chaque `--client-dir` est inspecté pour sa structure
  (transcriptions, caches d'outils, journaux MCP, configuration).
- `--since` : début de la période analysée (défaut `2026-10-10T00:00:00Z`).
- `--map cursor:user-monserveur=io.github.org/serveur` : relier à la main un nom de serveur local à un `server_id` du
  journal. Cette correspondance reste une **affirmation de votre part** ; elle est consignée comme telle dans
  `artifacts/extract/mapping_provenance.json`.
- Les correspondances possibles trouvées par empreinte se trouvent dans `artifacts/extract/suggestions.json`. C'est une
  DÉDUCTION, jamais appliquée automatiquement.
- `--redact-paths` : remplace les chemins de vos fichiers par une empreinte, pour partager le dossier. Le niveau 2
  (`--sources`) devient alors impossible.

## Lire votre dossier

`RESULT.md` liste chaque appel avec un verdict :

| Verdict | Sens |
|---|---|
| **FAIT** | La définition de l'outil présentée à votre client avant l'appel a une empreinte identique à une empreinte signée du journal. C'est l'identité d'un contenu, pas une preuve de ce que le modèle en a fait. |
| **DÉDUCTION** | L'appel est encadré par deux observations signées de la même version. Un aller-retour non observé entre les deux n'est pas exclu. |
| **DANS_UN_TROU** | La version a changé entre les deux observations signées qui encadrent l'appel. Version inconnue, deux candidates. |
| **UNOBSERVED** | L'appel est postérieur à la dernière observation signée du bundle. |
| **UNKNOWN** | Aucune feuille signée ne peut être reliée à l'appel (serveur absent du journal, pas de `--server-id`, heure inconnue ou incohérente). **UNKNOWN n'est jamais compté comme 0 exposition.** |
| **CONTRADICTION** | La définition présentée ne correspond pas à ce que la chronologie signée laisse déduire. |

Pour chaque feuille de changement du serveur, la position de l'appel est indiquée par **AVANT**, **APRÈS** ou
**DANS_UN_TROU**. C'est une **DÉDUCTION** : l'heure exacte d'un changement n'est pas connue. Seule une fenêtre l'est,
entre la dernière observation signée de l'ancienne version et la première de la nouvelle. Elle est bornée par les trous
publiés de la couverture (cycles `NOT_OBSERVED` / `MISSED` et période après la dernière tête).

« Appel pendant que la version X était en service » est donc toujours une déduction bornée par ces trous, sauf le cas
FAIT, qui porte sur la définition reçue par votre client.

## Vérifier hors ligne (vous, ou un tiers sans vos fichiers)

```sh
unshare -rn sh ~/mon-dossier-exposure/VERIFY.sh                                  # niveau 1
unshare -rn sh exposure-scan.sh --verify ~/mon-dossier-exposure --log-bundle ../legion-log-demo-34964
sh ~/mon-dossier-exposure/VERIFY.sh --sources                                   # niveau 2 : sur votre machine seulement
```

- **Niveau 1** (`VERIFY.sh`), sans vos fichiers locaux ni réseau :
  - les fichiers du MANIFEST sont présents et intacts ;
  - les signatures des feuilles et de la tête sont valides ;
  - les preuves d'inclusion RFC 6962 sont correctes ;
  - la couverture signée est vérifiée ;
  - une re-dérivation complète redonne `result.json` et `RESULT.md` à l'identique.

  Le contrôle échoue si un fichier bouge, si une preuve manque ou si une conclusion ne correspond plus.
- **Croisement** (`--verify ... --log-bundle`) : les fichiers signés du dossier doivent être identiques à ceux du bundle
  publié.
- **Niveau 2** (`--sources`) : relit les préfixes de vos transcriptions et refait l'extraction.

## Limites

- **Fichiers locaux non signés.** Transcriptions, journaux clients, caches, configurations et mtimes sont modifiables.
  Une extraction falsifiée de bout en bout passe le niveau 1. Seul le niveau 2, sur la machine d'origine, la détecte.
- **Authenticité du journal.** Elle repose sur la clé racine épinglée (`ROOT_PIN` dans `engine/vendor/verify_tlog.py`) et
  sur les empreintes `SHA256SUMS` / `BUNDLE_MANIFEST`. Ces valeurs sont à obtenir par un autre canal que l'archive
  elle-même.
- **Fraîcheur.** Le bundle s'arrête à sa tête (34964 feuilles, couverture 53 cycles). Tout appel postérieur est UNOBSERVED.
- **Couverture.** Seuls les serveurs présents dans le bundle ont une chronologie. Les autres sont UNKNOWN. Avec le bundle
  de démonstration, cela veut dire : tout serveur hors des 4 serveurs de la démo.
- **Bundle de démonstration.** La complétude d'un serveur est contrôlée par la chaîne `prev_leaf_index` et par les
  observations de la couverture signée. Une feuille à la fois dernière de sa chaîne et postérieure au dernier cycle de
  couverture pourrait être retirée sans être détectée. Seul le bundle complet recalcule la racine sur toutes les feuilles.
- **Exhaustivité.** Elle n'est pas prouvée : un appel absent de vos transcriptions n'est pas vu.
- **Impact.** Il reste inconnu : rien n'est lu des arguments ni des réponses.

## Ce que d'autres font déjà

Des outils côté client surveillent déjà les changements de définitions MCP : RugSnare, mcp-sentinel, Pipelock, entre
autres. exposure-scan ne prétend à aucune exclusivité. Son apport tient à un point : croiser vos appels passés avec un
**historique externe signé, qui publie ses trous**.
