# 📑 Système Multi-Couches de Détection des Menaces Cyber (Phishing URL & Malwares)

---

## 1. Introduction et Objectifs du Projet
Ce projet présente une solution de cybersécurité proactive basée sur l'Intelligence Artificielle et l'analyse structurelle réseau. L'objectif principal est de fournir un tableau de bord (Dashboard) capable d'analyser en temps réel deux vecteurs d'attaque majeurs :
1. **Les liens de Phishing (URLs)** : Via un réseau de neurones artificiels (Deep Learning).
2. **Les fichiers malveillants (Malwares)** : Via une analyse d'intégrité par empreinte numérique (Hash Matching SHA-256).

---

## 2. Architecture du Projet (Structure des Fichiers)
Le dépôt GitHub est structuré de manière professionnelle pour optimiser les performances de production :
* **`app.py`** : Le cœur de l'application Flask gérant le routage, l'aiguillage des requêtes HTTP et l'orchestration des pipelines.
* **`Url_Features.py`** : Script tactique d'extraction des caractéristiques vectorielles d'une URL.
* **`models/Malicious_URL_Prediction.h5`** : Le modèle de Deep Learning entraîné sous TensorFlow/Keras.
* **`Phishing-Extension/`** : Module d'extension de navigateur (Chrome/Edge) pour un scan passif en temps réel.
* **`templates/`** : L'interface utilisateur optimisée :
  * `index.html` : Portail de soumission (URL / Fichier).
  * `rapport_url.html` : Écran d'affichage de la pipeline en direct.
  * `rapport_fichier.html` : Rapport de scan de fichiers.
  * `history.html` : Registre centralisé triant dynamiquement les logs.

---

## 3. Pipeline d'Analyse des URLs (Explication en Détail)
Lorsqu'un utilisateur soumet une URL, celle-ci traverse une chaîne de traitement (Pipeline) composée de 5 étapes rigoureuses avant de délivrer le verdict :

### 🔍 Étape 1 : Brand Keywords & Détection de Spoofing
* **Mécanisme** : Le système utilise la bibliothèque `tldextract` pour isoler le nom de domaine principal (ex: `paypal`).
* **Sécurité** : Il compare ce domaine avec une liste de marques cibles. Si un mot-clé sensible est détecté dans une URL qui n'appartient pas officiellement à la marque (ex: `secure-login-paypal-update.com`), le système lève immédiatement une alerte de **Brand Spoofing**.

### 🔐 Étape 2 : Protocole & Longueur (Protocol & Length)
* **Mécanisme** : Analyse de la structure textuelle globale. Le système vérifie si le protocole sécurisé `HTTPS` est présent et calcule le nombre total de caractères. Les attaquants rallongent souvent les URLs pour masquer les jetons d'authentification falsifiés.

### 🔢 Étape 3 : Conversion ASCII en Binaire
* **Mécanisme** : Afin de préparer une représentation bas niveau du texte, le domaine est converti en octets binaires. Cela permet de visualiser mathématiquement la charge utile du texte de l'URL.

### 🌐 Étape 4 : Couche de Transport UDP (DNS Request)
* **Mécanisme** : Pour obtenir l'identité réseau réelle du serveur, le système simule une requête de résolution de nom au niveau de la couche de transport réseau via le protocole **UDP** sur le port standard **53**.

### 🖥️ Étape 5 : Cartographie DNS (DNS Mapping)
* **Mécanisme** : Résolution concrète du domaine en adresse IP publique grâce à la bibliothèque `socket`. Si le domaine échoue à fournir une adresse IP (`Échec DNS`), c'est un indicateur fort que le domaine de phishing est éphémère.

---

## 4. Le Moteur d'Intelligence Artificielle : Feature Vector
Le modèle de Deep Learning (`.h5`) ne lit pas directement le texte brut. Le script `Url_Features.py` transforme la structure de l'URL en un **Vecteur Numérique de 16 Dimensions (Features)** :

### Détail des 16 Features extraites :
1. **`hostname_length`** : Longueur du nom d'hôte.
2. **`url_length`** : Longueur totale de l'URL.
3. **`fd_length`** : Longueur du premier répertoire après le domaine.
4. **Comptage des caractères spéciaux** (9 caractéristiques distinctes calculant la fréquence d'apparition des symboles suspects utilisés pour tromper la victime) : `.` , `-` , `?` , `=` , `@` , `&` , `!` , `_` , `/`.
5. **`digit_count`** : Nombre total de chiffres (0-9).
6. **`letter_count`** : Nombre total de lettres.
7. **`no_of_dir`** : Nombre total de sous-répertoires dans le chemin réseau.
8. **`having_ip_address`** : Feature binaire (`1` ou `0`) indiquant si l'URL utilise directement une adresse IP brute au lieu d'un nom de domaine valide.

---

## 5. Module d'Inspection de Fichiers (Malware Analyzer)
Pour la partie détection de charges virales, l'application applique la méthodologie du **Hash Matching** (Recherche par signature) :

* **Calcul de l'empreinte** : Dès qu'un fichier est téléversé, son flux binaire est lu instantanément en mémoire vive pour mesurer sa taille exacte (évitant l'erreur des *0 Octets*) et calculer sa signature cryptographique unique via l'algorithme **SHA-256**.
* **Vérification** : Ce Hash est comparé à une base de données locale contenant les signatures des malwares connus (`MALWARE_HASHES`).
* **Verdicts professionnels différenciés** :
  * Pour les URLs : Les verdicts affichés sont **TRUE** (Sain) ou **FAKE** (Malveillant).
  * Pour les Fichiers : Les verdicts affichés sont **SAFE** (Sain) ou **MALICIOUS** (Dangereux).

---

## 6. Extension Cyber-Navigateur (Phishing Detector UI)
Pour étendre la portée du projet, une extension de navigateur autonome (compatible Chromium / Edge / Chrome) a été développée.
* Elle utilise un script d'arrière-plan (`popup.js`) lié à un fichier de configuration `manifest.json` pour intercepter dynamiquement l'URL de l'onglet actif de l'utilisateur et interroger l'API du Core Scanner.

---

## 7. Journal d'Historique à Double Matrice (Logs System)
L'interface de l'historique (`history.html`) implémente un système de tri intelligent. Au lieu d'afficher une liste brute, la page sépare dynamiquement les données en deux tableaux hermétiques :
1. **Tableau Vert (Éléments Sains)** : Regroupe les analyses ayant obtenu le label `TRUE` ou `SAFE`.
2. **Tableau Rouge (Menaces Identifiées)** : Isole de manière critique toutes les activités suspectes (`FAKE` / `MALICIOUS`).