# Chiffrement et cryptographie — guide technique pour "Matt-daemon"

Ce document explique, pour une personne novice en cryptographie, les concepts, les choix techniques et la manière dont le chiffrement est implémenté dans ce projet (où regarder dans le code, comment tester, risques et bonnes pratiques).

Le code du projet utilise :
- X25519 (ECDH) pour l'échange de clés (asymétrique)
- HKDF-SHA256 pour dériver une clé symétrrique depuis le secret partagé
- AES-256-GCM pour le chiffrement symétrique (AEAD — chiffrement + authentification)
- Nonce construit depuis un compteur (IV 12 octets = 4 octets de 0 + 8 octets de counter)

Les fichiers utiles dans le dépôt :
- `libftpp/includes/crypto.hpp` (déclarations des helpers crypto)
- `libftpp/srcs/client.cpp` (handshake et envoi chiffré côté client)
- `libftpp/srcs/server.cpp` (handshake et déchiffrement côté serveur)
- `libftpp/includes/message.hpp` (format des messages applicatifs)

---

## Table des matières

1. Vue d’ensemble du flux
2. Principes et définitions (nonce, IV, asymétrique, symétrique, courbe elliptique, AEAD, tag)
3. Détails du protocole utilisé dans le projet
4. Format des messages (en‑tête, payload)
5. Séquence handshake (pas-à-pas)
6. Pourquoi AES‑GCM et X25519 ? avantages et limites
7. Tests & vérification (tcpdump / Wireshark / challenge-response)
8. Risques, erreurs courantes et recommandations
9. Glossaire succinct
10. Références / lectures recommandées

---

## 1. Vue d’ensemble du flux

1. Client se connecte au serveur socket TCP.
2. Serveur envoie sa clé publique X25519 (32 octets).
3. Client génère sa paire X25519 (pub/priv), envoie sa clé publique au serveur.
4. Les deux côtés utilisent X25519 (ECDH) pour dériver un secret partagé.
5. Chaque côté applique HKDF-SHA256 sur le secret pour produire une clé symétrique de 32 octets.
6. Le client et le serveur utilisent AES-256-GCM avec cette clé pour chiffrer/déchiffrer les payloads des messages applicatifs. Un compteur (uint64) sert à générer un nonce unique par message (IV de 12 octets).

À partir de là, l’application échange des `Message` : si la session est chiffrée, le payload envoyé est `ciphertext || tag` (tag de 16 octets). Sinon le payload est le plaintext.

---

## 2. Principes et définitions (explications simples)

- Asymétrique vs Symétrique
  - Chiffrement symétrique : même clé pour chiffrer et déchiffrer. Rapide, utilisé pour chiffrer les paquets (ex. AES).
  - Chiffrement asymétrique : paire de clés (publique / privée). On peut échanger des clés ou vérifier identité. Ex : RSA, X25519.

- Courbes elliptiques (Elliptic Curve)
  - Méthode d’algèbres qui permet des opérations cryptographiques avec petites clés et forte sécurité. X25519 est une courbe spécifique (Curve25519) conçue pour l’échange de clés ECDH.

- X25519 (ECDH)
  - Permet à deux parties de dériver un secret partagé en combinant leur clé privée et la clé publique de l’autre. Le secret n’est jamais transmis sur le réseau.

- HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
  - Méthode standard pour dériver des clés symétriques à partir d’un secret initial (ici le secret X25519). HKDF-SHA256 utilise SHA-256 comme fonction de hachage.

- Nonce & IV
  - IV (Initialisation Vector) et nonce (number used once) désignent souvent la même chose : une valeur qui doit être unique pour chaque chiffrement avec une même clé.
  - Pour AES-GCM, l’IV doit être unique pour chaque message et idéalement non prévisible.
  - Ici on construit un IV de 12 octets = 4 octets (0x00000000) || 8 octets (counter big-endian). Le compteur (uint64) change à chaque message émis.

- AES‑GCM (Galois/Counter Mode)
  - Mode de chiffrement symétrique qui fournit à la fois confidentialité (chiffrement) et intégrité/authentification via un tag (16 octets). On parle d’AEAD (Authenticated Encryption with Associated Data).
  - AAD (Associated Authenticated Data) est facultatif : il s’agit de données ajoutées à l’authentification mais pas chiffrées (par ex. en-tête). Dans ce projet, l’en-tête n’est pas clairement passée en AAD — c’est une amélioration potentielle.

- Tag
  - Court code (souvent 16 octets en GCM) joint au ciphertext, permettant de vérifier que le ciphertext n’a pas été modifié et qu’il a bien été généré avec la même clé/nonce.

---

## 3. Détails du protocole employé dans le projet

- Échange de clés :
  - Serveur possède une clé privée persistante (chargée depuis `server_key.pem` si présente). Il calcule la clé publique (raw public 32 bytes) et l’envoie au client.
  - Client génère une paire éphémère X25519, envoie sa clé publique au serveur.
  - Les deux côtés calculent `shared = X25519(priv_self, pub_peer)`.
  - Appliquer `HKDF-SHA256(shared, "matt-daemon session")` -> out_key (32 bytes) = clé AES-256.

- Nonce / compteur :
  - Les deux côtés maintiennent `send_counter` et `recv_counter` (uint64).
  - Le nonce utilisé pour AES-GCM = 4 octets zéro || counter (8 octets big-endian). On incrémente `send_counter` à chaque encryption ; on incrémente `recv_counter` lors d’un déchiffrement réussi.

- Format réseau du `Message` :
  - HEADER (8 octets): int (type) + uint32_t (data_size). `Message::writeHeader()` écrit la taille en host byte order.
  - BODY (data_size octets): soit plaintext, soit ciphertext + tag (si chiffré).

---

## 4. Format des messages (exemples concrets)

- Exemple : envoyer un texte `from` + `text`
  - Sérialisation `Message` pour une chaîne : écrit d’abord un uint32_t size (taille string), puis les octets de la string.
  - Si `from = "hugo"` et `text = "oui"`, le payload clair contiendrait (interpretable) :
    - 4 bytes (size of "hugo") = 4
    - 4 bytes 'hugo'
    - 4 bytes (size of "oui") = 3
    - 3 bytes 'oui'
    - => plaintext_len = 4 + 4 + 4 + 3 = 15 bytes
  - Si session chiffrée, le client calcule ciphertext de 15 octets et ajoute tag 16 octets => payload envoyé = 31 octets.

- Header total envoyé (host byte order): 8 bytes header + 31 bytes body = 39 bytes (taille globale sur la couche transport). Ton tcpdump peut afficher des longueurs proches selon segmentation TCP.

---

## 5. Handshake détaillé (pas-à-pas)

1. Serveur : chargement ou génération de la paire X25519.
2. Serveur envoie `server_pub` (32 octets) directement sur le socket après accept.
3. Client lit `server_pub` (32 octets), génère `client_pub`/`client_priv` et envoie `client_pub` (32 octets) au serveur.
4. Les deux calculent `shared = derive_x25519_shared(priv_self, pub_peer)`.
5. `hkdf_sha256(shared, "matt-daemon session", key, 32)` pour dériver la clé 32 octets.
6. Serveur stocke `ClientSession` { encrypted = true, key, send_counter=1, recv_counter=1 }.
7. Client active `_encrypted = true` et initialise ses compteurs.

Après ceci, les payloads sont chiffrés par AES-GCM en utilisant (key, nonce(counter)).

---

## 6. Avantages & raisons des choix

- X25519 : sécurisé, rapide, clé courte (32 bytes) et bien supporté par OpenSSL.
- HKDF-SHA256 : standard pour dérivation de clé (permets d'ajouter du 'context info' pour séparer usages de clé).
- AES‑GCM : mode AEAD répandu (confidentialité + intégrité), bon support matériel/logiciel.

Limites :
- GCM nécessite des nonces uniques ; si réutilisés, sécurité compromise.
- AAD non utilisé pour l’en‑tête — l’en‑tête pourrait être falsifiée sur le chemin si elle n’est pas protégée par l’auth tag.

---

## 7. Comment vérifier / tester que c’est chiffré (pratique)

1. Vérification simple par taille (déjà loggée) : si header indique `data_size = plaintext_len + 16` et serveur réussit déchiffrement -> preuve forte.
2. Utiliser `tcpdump` / Wireshark et :
   - Capturer sur le port 6668 (`tcpdump -s 0 -w /tmp/cap.pcap -i any port 6668`).
   - Ouvrir dans Wireshark et `Follow → TCP Stream` en `Hex Dump`.
   - Si le chunk applicatif est illisible et a la longueur `plaintext + 16`, c’est du ciphertext+tag.
3. Implémenter challenge-response :
   - Le serveur envoie nonce `N` (plaintext) avec `COMMAND` (ex: "CHAL").
   - Client renvoie `CHAL_RESP` contenant `N` via son chemin chiffré. Si serveur déchiffre et retrouve `N`, preuve solide de chiffrement.

---

## 8. Erreurs courantes / risques réels

- Réutiliser la même clé/nonce pour plusieurs messages (compromet GCM).
- Ne pas protéger l’en‑tête (size/type) en AAD : un adversaire pourrait altérer l’en‑tête et tromper le récepteur.
- Stocker les clés privées sans protection (ex: `server_key.pem` accessible) : conserver avec permissions 600 et hors VCS.
- Ne pas vérifier le tag correctement : si déchiffrement renvoie `false`, ne pas traiter le plaintext.

---

## 9. Recommandations/Bonnes pratiques

- Protéger `server_key.pem` : chmod 600 et ne pas le committer.
- Convertir les champs de taille du header en network byte order (htonl/ntohl) pour meilleure interopérabilité.
- Passer le header (type/size) en AAD dans AES‑GCM pour l’authentifier.
- Mettre en place une rotation de clé (nouveau handshake) avant que le compteur 64‑bits arrive à une grande valeur ou après X octets échangés.
- Ajouter des tests unitaires pour l’API crypto.

---

## 10. Glossaire

- Nonce : valeur unique pour chaque opération de chiffrement avec la même clé. Souvent utilisée comme IV.
- IV (Initialization Vector) : vecteur d'initialisation, souvent synonyme de nonce selon le contexte.
- Asymétrique : crypto à paire de clés (pub/priv). Sert à l’échange de clé et à l’authentification.
- Symétrique : crypto avec une même clé pour chiffrer/déchiffrer (AES).
- Courbe elliptique : structure mathématique utilisée pour obtenir sécurité élevée avec des clés courtes (ex: Curve25519).
- AEAD : Authenticated Encryption with Associated Data (ex: AES-GCM) — chiffre + authentifie.
- Tag : code d’authentification (ex: 16 octets) vérifié au déchiffrement.
- HKDF : KDF standard pour dériver des clés depuis un secret.

---

## 11. Références utiles

- RFC 7748 — X25519
- RFC 5869 — HKDF
- NIST SP 800‑38D — Galois/Counter Mode (GCM)
- OpenSSL docs: `EVP_Encrypt*`, `EVP_Decrypt*`, `RAND_bytes`
- "Cryptography Engineering" — Bruce Schneier (livre)

---

## 12. Exemple rapide : workflow de debug (commande)

1. Lancer le serveur : `./build/launch_serv` (ou équivalent)
2. Lancer la GUI client et se connecter
3. Capturer :
```bash
sudo tcpdump -s 0 -w /tmp/matt.pcap -i any port 6668
# envoyer un message depuis la GUI, arrêter la capture après
wireshark /tmp/matt.pcap
```
4. Dans Wireshark : `Follow` → `TCP Stream` → `Hex Dump` pour voir le payload
