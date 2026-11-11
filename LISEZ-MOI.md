# Surligneur — devoirs.norvy.app

Carnet de révision avec IA : scan des cours (photos iPhone, PDF même scanné, Word), classement par matière, fiches de révision automatiques, quiz, exercices corrigés, Prof IA, devoirs (aide pour démarrer + correction de la copie), planning de révision, niveau par matière, et suivi parent.

Hébergement : **Cloudflare Workers** (gratuit) — pages `public/`, serveur `worker/index.js`, base **D1**. Chaque modification poussée sur `main` est déployée automatiquement. L'IA passe par **votre clé API Claude**, gardée en secret sur le serveur : elle n'est jamais envoyée au navigateur.

## Mise en ligne (une seule fois)

1. Cloudflare → Workers & Pages → **Créer** → **Importer un dépôt** → `KCOACHING02/surligneur` (commande de déploiement par défaut : `npx wrangler deploy`). La base D1 `surligneur` est créée automatiquement.
2. Worker → Paramètres → **Variables et secrets** : ajouter deux secrets
   - `ANTHROPIC_API_KEY` : votre clé API (console.anthropic.com → API Keys)
   - `INSTALL_TOKEN` : un mot de votre choix (sert uniquement à créer les comptes)
3. Worker → Paramètres → **Domaines et routes** → domaine personnalisé `devoirs.norvy.app` (ajouter l'enregistrement CNAME indiqué dans la zone DNS norvy.app chez Gandi).
4. Ouvrir `https://devoirs.norvy.app/install?token=VOTRE_TOKEN` : créer le compte parent et le(s) compte(s) élève. La même page sert plus tard à changer un mot de passe.
5. iPhone : Safari → Partager → « Sur l'écran d'accueil ». Android : Chrome → ⋮ → « Installer l'application ».

## Réglages (wrangler.jsonc → vars)

- `MODEL_QUICK`, `MODEL_DEFAULT`, `MODEL_COMPLEX` : modèles Claude utilisés (classement rapide / fiches, quiz, exercices / correction des copies).
- `DAILY_AI_LIMIT` : nombre maximum de demandes à l'IA par élève et par jour (0 = illimité). Le compte parent n'est pas limité.

La consommation de l'IA (demandes, jetons, images) est visible dans l'onglet **Suivi des élèves** du compte parent ; le coût exact en euros sur console.anthropic.com.

## Test en local

```
npm install
printf 'INSTALL_TOKEN=test\nANTHROPIC_API_KEY=sk-ant-...\n' > .dev.vars
npx wrangler dev
```
Puis ouvrir `http://localhost:8787/install?token=test`.
