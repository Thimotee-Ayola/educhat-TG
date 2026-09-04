# EduChat Togo — Base de départ

## Ce qui fonctionne déjà
- Inscription par nom d'utilisateur + mot de passe (aucun numéro de téléphone demandé)
- Mot de passe haché en sécurité (jamais stocké en clair)
- Double authentification (2FA) obligatoire à chaque connexion via une appli comme Google Authenticator
- Squelette serveur pour la vérification par empreinte/visage (WebAuthn) sur un nouvel appareil
- Messagerie simple entre deux comptes, avec messages chiffrés au repos dans la base de données
- Design sombre aux couleurs du Togo (vert / jaune / rouge)

## Ce qui est fait, et ce qui reste à valider en conditions réelles
1. **Empreinte/visage (WebAuthn)** : entièrement codé (serveur Python + petit
   pont JavaScript obligatoire qui parle au capteur du téléphone/ordinateur —
   ceci est impossible à faire en pur Python, même WhatsApp ou une appli
   bancaire passent par ce même mécanisme du navigateur/OS). Le code est
   complet, mais comme je n'ai pas d'accès internet pour tester en direct sur
   un vrai appareil, il faudra faire un premier essai après déploiement et me
   montrer le message d'erreur exact si quelque chose coince — c'est normal
   pour ce type d'intégration, même pour des développeurs professionnels.
2. **Chiffrement de bout en bout** : actuellement, les messages sont chiffrés
   "au repos" (dans la base de données) avec une clé côté serveur. Ce n'est PAS
   encore un chiffrement de bout en bout comme Signal/WhatsApp, où même le
   serveur ne peut pas lire les messages. C'est l'étape suivante logique.
3. Pas encore de photo de profil, notifications, groupes, etc.

## Déployer sur Render
1. Mets tout ce dossier sur GitHub (dépôt `educhat-togo` par exemple)
2. Sur Render : New + → Web Service → connecte ton dépôt GitHub
3. Configuration :
   - Build Command : `pip install -r requirements.txt`
   - Start Command : `gunicorn app:app`
   - Plan : Free
4. Dans l'onglet **Environment**, ajoute ces variables :
   - `RP_ID` = le domaine Render de ton appli (ex: `educhat-togo.onrender.com`, SANS https://)
   - `ORIGIN` = `https://educhat-togo.onrender.com`
   - `SECRET_KEY` = une longue chaîne aléatoire (ex: générée avec `python3 -c "import secrets; print(secrets.token_hex(32))"`)
   - `FERNET_KEY` = générée avec `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
5. Déploie — ton appli sera en ligne à l'URL choisie

## Prochaine étape recommandée
Teste d'abord l'inscription, le mot de passe et la 2FA (déjà fonctionnels).
Une fois que ça marche bien, on finalise ensemble la partie empreinte/visage
avec la librairie JavaScript, puis on passe au vrai chiffrement de bout en bout.
