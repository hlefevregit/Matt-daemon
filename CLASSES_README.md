# Documentation technique : classes Message, Server, Client

Ce document décrit de façon technique et pratique trois composants centraux du projet :

- `Message` (sérialisation / format réseau)
- `Server` (acceptation connexions, handshake, réception, dispatch)
- `Client` (connexion, handshake, envoi, réception)

Pour chaque classe je décris : responsabilités, API publique principale (méthodes), champs importants, exemples d'utilisation, et pièges/limitations à connaître.

---

## 1) `Message` — format et sérialisation

Fichiers : `libftpp/includes/message.hpp`, `libftpp/includes/message.tpp`, `libftpp/srcs/message.cpp`

But
- Encapsuler un buffer d'octets (`std::vector<uint8_t> _data`) contenant une en‑tête (type + taille) et un payload.
- Offrir des opérateurs `<<` / `>>` pour sérialiser/desérialiser types primitifs et `std::string`.
- Gérer un pointeur de lecture mutable `_readPos` pour permettre la lecture depuis `const Message&`.

Structure interne
- champ privé `_data` : le buffer complet (header + payload).
- `_type` : `int` (enum Message::Type expose UNKNOWN, TEXT, BINARY, COMMAND).
- `mutable size_t _readPos` : position de lecture dans `_data` (mutable pour `operator>>` étant `const`).

Constantes
- `static const size_t HEADER_SIZE = sizeof(int) + sizeof(uint32_t)` — header = type + size.
- `static const size_t MAX_DATA_SIZE` — protection contre payload trop grand.

Méthodes clés (publiques)
- Constructeurs : `Message()`, `Message(int)`, `Message(Type)` — initialisent header via `writeHeader()`.
- `const std::vector<uint8_t>& rawData() const` — renvoie le buffer interne (header+payload). Utilisé pour l'envoi socket.
- `getData()` / `getDataSize()` — accès au payload (getData() retourne _data entier ; getDataSize() soustrait HEADER_SIZE).
- `void clear()` — réinitialise `_data` et `_type` à UNKNOWN et écrit header.
- `void resetData()` — raccourcit `_data` à `HEADER_SIZE` et met readPos à `HEADER_SIZE`.
- `ensureCapacity(size_t)` / `appendData(const uint8_t*, size_t)` — utiles pour construire message depuis bytes bruts (ex : déchiffrement côté serveur).

Sérialisation / opérateurs
- `template<typename T> Message& operator<<(const T& data)` — sérialise la valeur binaire `T` (sizeof(T) bytes) dans `_data`, puis appelle `writeHeader()`.
- `Message& operator<<(const std::string& data)` — écrit `uint32_t size` puis les bytes de la string.
- `template<typename T> Message& operator>>(T& data) const` — lit `sizeof(T)` octets depuis `_readPos` (avec `checkReadBounds`) et incrémente `_readPos`.
- `Message& operator>>(std::string& data) const` — lit d'abord `uint32_t size`, puis `size` octets.

Points importants / pièges
- `operator>>` est `const` et utilise `_readPos` mutable : pratique pour handlers qui reçoivent `const Message&`.
- `writeHeader()` réécrit le champ `type` et `dataSize` en place ; le code courant écrit la taille en host byte order — attention si client et serveur sont sur architectures différentes (utiliser `htonl/ntohl` pour robustesse si nécessaire).
- Quand on construit un `Message` côté réception (p.ex. sur serveur), prendre soin de l'ordre : si tu veux initialiser le payload puis définir le type, utilise `clear()` puis `appendData(...)` puis `setType(msgType)` afin que `writeHeader()` contienne la bonne taille.
- `MAX_DATA_SIZE` protège contre attaques ou corruption mémoire.

Exemple d'utilisation
```cpp
Message out(Message::Type::TEXT);
out << std::string("alice") << std::string("Bonjour tout le monde");
client.send(out); // client.send utilise out.rawData() pour le socket

// côté réception handler (const Message& m)
std::string from, text;
Message copy = m; // si besoin d'une copie
copy >> from >> text;
```

---

## 2) `Client` — connexion, handshake, envoi, réception

Fichiers : `libftpp/includes/client.hpp`, `libftpp/srcs/client.cpp`

Responsabilités
- Gérer le socket client, établir connexion TCP vers le serveur.
- Effectuer le handshake X25519 (lire server_pub, envoyer client_pub, dériver la clé de session).
- Maintenir état de chiffrement : `_encrypted`, `_session_key[32]`, `_send_counter`, `_recv_counter`.
- Envoyer `Message` (chiffrer le payload si session chiffrée).
- Recevoir octets en background (`recvLoop` thread), pousser dans `_recv_buffer` et laisser `update()` assembler messages et appeler handlers.
- Permettre d'enregistrer des actions (handlers) par type de message via `defineAction`.

Champs importants (publics/privés)
- `_socket_fd`, `_ip_address`, `_port`, `_connected`
- `_encrypted` (bool), `_session_key[32]`, `_send_counter`, `_recv_counter`
- `_recv_buffer` : vector<uint8_t> — buffer tampon des octets réseau non traités
- `_recv_thread`, `_stop_recv_thread` : thread qui lit socket et insère dans `_recv_buffer`
- `_send_mutex` / `_recv_mutex` : mutex pour protéger opérations réseau et accès au buffer
- `_actions` : `unordered_map<Message::Type, std::function<void(const Message&)>>` — mapping type => handler

Handshake
- `Client::connect()` crée socket, connect(), puis lit 32 octets (server_pub), génère client keypair, envoie client_pub, dérive shared via `ftcrypto::derive_x25519_shared`, puis `ftcrypto::hkdf_sha256` pour obtenir `_session_key`.
- Si tout va bien `_encrypted = true` et counters initialisés.

Envoi (`Client::send`)
- Si `_encrypted` true et `_session_key` non-nul, extrait header+payload via `message.rawData()`.
- Extrait payload_size depuis header, construit `payload = full.data() + HEADER_SIZE`.
- Appelle `ftcrypto::aes256gcm_encrypt(_session_key, _send_counter, payload, payload_size, cipher, tag)`.
- Si chiffrement OK : construit un buffer `out = header + (cipher||tag)` et met à jour la taille dans header (taille = cipher.size()+tag.size()).
- Incrémente `_send_counter` après envoi réussi.
- Sinon : envoie plaintext fallback.

Réception et dispatch
- `recvLoop` lit depuis socket (blocking/non-blocking selon config) et pousse octets dans `_recv_buffer` sous `_recv_mutex`.
- `update()` (appelé régulièrement par l'application, ex. main loop GUI) assemble messages en lisant header (type,int + size,uint32) puis si `HEADER_SIZE + msg_size` disponible, construit `Message` : `clear()`, `ensureCapacity(msg_size)`, `appendData(payload, msg_size)`, `setType(msg_type)` (ordre important), puis `handleMessage(message)`.
- `handleMessage` look up `_actions` et invoque handler `it->second(message)`.

Définir handlers
- `defineAction(Message::Type t, std::function<void(const Message&)>)` — copie le callable dans `_actions[t]`.
- Le callable reçoit `const Message&` (le Message peut être copié si on veut l'utiliser plusieurs fois).

Thread-safety et recommandations
- Bloquer `_send_mutex` autour des envois socket pour éviter mélanges de paquets.
- Protéger `_recv_buffer` par `_recv_mutex`.
- Si on manipule `_actions` dynamiquement (ajout/retrait après démarrage du recv thread), envisager un mutex `_actions_mutex` pour protéger lecture/écriture concurrente (dans ce code, `defineAction` n'utilise pas mutex — ajouter si handlers sont ajoutés après le lancement du client dans un contexte multi‑thread).

Pièges spécifiques
- Assurez-vous que `Message::writeHeader()` et la lecture dans `update()` utilisent le même endianness. Actuellement la taille est écrite en host byte order.
- Ne pas capturer par référence des variables locales dans une lambda passée à `defineAction` si ces locales vont sortir de scope.

Exemple
```cpp
client.defineAction(Message::Type::TEXT, [](const Message& m){
    Message copy = m;
    std::string from, text;
    copy >> from >> text;
    printf("%s: %s\n", from.c_str(), text.c_str());
});

Message out(Message::Type::TEXT);
out << std::string("hugo") << std::string("Salut");
client.send(out);
```

---

## 3) `Server` — acceptation, handshake, réception, dispatch et envoi

Fichiers : `libftpp/includes/server.hpp`, `libftpp/srcs/server.cpp`

Responsabilités
- Écouter sur un port, accepter connexions et effectuer handshake X25519 (envoyer pub, lire client pub, dériver clé).
- Maintenir collection `_clients` (map clientID -> socket) et `_sessions` (session par client : clé, encrypted, compteurs).
- Lire données depuis clients (via `select` dans `updateLoop`), assembler messages et placer dans `_pendingMessages`.
- Dispatcher les messages au thread principal via `update()` qui appelle handlers enregistrés dans `_actions`.
- Envoyer messages aux clients via `sendTo`, `sendToArray`, `sendToAll` — encrypte avant envoi si session présente et active.

Champs importants
- `_listeningSocket`, `_isRunning`, `_updateThread` — gestion serveur
- `_clients` : `unordered_map<long long, int>` (clientID -> socket)
- `_sessions` : `unordered_map<long long, ClientSession>` (clé, encrypted flag, send/recv counters)
- `_actions` : `unordered_map<Message::Type, std::function<void(long long&, const Message&)>>` — mapping type -> handler(clientID, msg)
- `_pendingMessages` : vecteur de paires (clientID, Message) où `receiveFromClient` pousse messages pour traitement par `update()`

Flux réception
- `updateLoop` : select() sur listening socket et sockets clients → appel `acceptNewClient()` ou `receiveFromClient(clientID, clientSocket)`.
- `receiveFromClient` : lit octets, parse header(s) dans la donnée lue (peut contenir plusieurs messages ou partiels), pour chaque message :
  - construit `Message msg` puis récupère le payload (payload vector)
  - si `_sessions[clientID].encrypted` essaye `aes256gcm_decrypt(..., recv_counter, cipher, cipherlen, tag, 16, plain)`
    - si déchiffrement OK : `msg.appendData(plain.data(), plain.size())` et incrémente `recv_counter`
    - sinon : fallback logging / append raw payload
  - pousse `(clientID, msg)` dans `_pendingMessages` sous `_clientsMutex`.
- `update()` (exécuté par le thread principal) swappe `_pendingMessages` et traite chaque `(clientID,msg)` en recherchant un handler dans `_actions` et en appelant `action(clientID,msg)`.

Envoi (`sendTo`)
- Si la session du destinataire est chiffrée : récupère payload_size (depuis message.getData() header), lit payload plaintext, appelle `aes256gcm_encrypt(session.key, counter, payload, payload_size, cipher, tag)`, construit out buffer = header (mise à jour size) + cipher + tag, incrémente send_counter et envoie.
- Sinon : envoie en plaintext (raw message.getData()).

Définir handlers
- `defineAction(Message::Type, std::function<void(long long&, const Message&)>)` : stocke la fonction dans `_actions` (protégé par `_actionsMutex`). Le handler a le `clientID` pour savoir qui a envoyé le message.

Exemple courant (broadcast TEXT handler)
```cpp
server.defineAction(Message::Type::TEXT, [this](long long& clientID, const Message& msg){
    Message m = msg; // copie
    std::string from, text;
    m >> from >> text;

    Message out(Message::Type::TEXT);
    out << from << text;
    // send to everyone except sender
    std::vector<long long> recipients;
    {
        std::lock_guard<std::mutex> lk(_clientsMutex);
        for (auto &p : _clients) if (p.first != clientID) recipients.push_back(p.first);
    }
    sendToArray(out, recipients);
});
```

Pièges / recommandations serveur
- Toujours protéger `_clients` et `_sessions` par mutex quand on y accède depuis plusieurs threads.
- Valider les tailles avant d'appendData pour éviter overflow.
- Ne pas accepter des `Message` dont le `msgSize` dépassent `MAX_DATA_SIZE`.
- Pour sécurité : ne pas logguer de plaintext produit par déchiffrement en production — utile uniquement pour debug.

---

## 4) Interactions entre Message / Client / Server — scénarios pratiques

1. Envoi simple texte :
   - Côté client : construire `Message(Message::Type::TEXT)` puis `<< from << text` et `client.send(out)`.
   - `Client::send` chiffre (si session active) et écrit header+payload ciphertext+tag sur socket.
   - Serveur reçoit, `aes256gcm_decrypt` vérifie tag et retourne plaintext dans `Message` puis `_pendingMessages`.
   - `update()` appelle handler correspondant (p.ex. broadcast à autres clients).

2. Command request (CHECK_USERNAME) :
   - Client construit `Message::Type::COMMAND` et sérialise `"CHECK_USERNAME"` + username.
   - Serveur lit le message dans `receiveFromClient` (le traitement des commandes peut être en clair ou en chiffré selon la session).
   - Serveur traite la commande et `sendTo` client une réponse `Message::Type::COMMAND`.

---

## 5) Tests utiles et points de debugging

- Pour debug réseau utiliser `tcpdump` / `tshark` / `wireshark` sur le port 6668. Voir `ENCRYPTION.md` pour détails.
- Si un message n'est pas traité : vérifier que `Message::getType()` correspond bien au type attendu par `_actions` (attention à conversion int -> Message::Type).
- Si un handler ne se déclenche pas, inspecter l'ordre `clear/appendData/setType` lors de la reconstruction d'un `Message` (le code client a été corrigé pour `clear(); appendData(...); setType(type);`).

---

## 6) Checklist rapide pour l'ajout d'un nouveau handler

1. Définir handler côté serveur avec `defineAction(Message::Type::X, handler)` en s'assurant d'acquérir `_actionsMutex` si modification dynamique.
2. Dans handler : copier `Message m = msg;` pour pouvoir effectuer plusieurs `>>` / lectures.
3. Extraire champs via `m >> field1 >> field2;` et agir (accès à clientID pour répondre).
4. Pour répondre : construire `Message reply(Type::COMMAND)` puis `reply << ...; sendTo(reply, clientID)`.

---

## 7) Fichiers sources principaux (référence rapide)
- `libftpp/includes/message.hpp` / `message.tpp` / `srcs/message.cpp`
- `libftpp/includes/client.hpp` / `srcs/client.cpp`
- `libftpp/includes/server.hpp` / `srcs/server.cpp`
- `libftpp/includes/crypto.hpp` (helpers crypto)

---

## 8) Questions fréquentes et réponses rapides
- Q : Où je lis le contenu d'un `Message` reçu dans un handler ?
  - R : `Message copy = msg; copy >> field1 >> field2;` (operator>> est `const`).

- Q : Comment j'envoie un message chiffré ?
  - R : Construis `Message` normalement et appelle `client.send(message)` ; la couche `Client` chiffre automatiquement si `_encrypted == true`.

- Q : Pourquoi je ne vois pas de handler appelé pour mon type ?
  - R : Vérifie que tu as bien appelé `defineAction` avec le même `Message::Type` et qu'il est enregistré avant que `update()` ne traite les messages. Vérifie aussi l'endianness du header si messages interop.


---
