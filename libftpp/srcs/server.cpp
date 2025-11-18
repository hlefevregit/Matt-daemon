/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   server.cpp                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hugo <hugo@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/14 11:46:55 by hulefevr          #+#    #+#             */
/*   Updated: 2025/11/18 17:58:56 by hugo             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/server.hpp"
#include "../includes/crypto.hpp"

// small helpers for logging
static std::string hex_encode(const unsigned char* data, size_t len) {
	std::string s;
	s.reserve(len * 2);
	const char hex[] = "0123456789abcdef";
	for (size_t i = 0; i < len; ++i) {
		unsigned char b = data[i];
		s.push_back(hex[(b >> 4) & 0xF]);
		s.push_back(hex[b & 0xF]);
	}
	return s;
}

static bool is_printable_text(const unsigned char* data, size_t len) {
	for (size_t i = 0; i < len; ++i) {
		unsigned char c = data[i];
		if (c == '\n' || c == '\r' || c == '\t') continue;
		if (c < 32 || c > 126) return false;
	}
	return true;
}

Server::Server() : _listeningSocket(-1), _isRunning(false), _nextClientID(1) {}

Server::~Server() {
	stop();
}

void Server::start(const size_t& p_port) {
	if (_isRunning.load()) {
		std::cerr << "Server is already running." << std::endl;
		return;
	}

	_listeningSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (_listeningSocket < 0) {
		std::cerr << "Failed to create socket." << std::endl;
		return;
	}

	sockaddr_in serverAddr;
	std::memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = INADDR_ANY;
	serverAddr.sin_port = htons(p_port);

	if (bind(_listeningSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
		std::cerr << "Failed to bind socket." << std::endl;
		close(_listeningSocket);
		_listeningSocket = -1;
		return;
	}

	if (listen(_listeningSocket, SOMAXCONN) < 0) {
		std::cerr << "Failed to listen on socket." << std::endl;
		close(_listeningSocket);
		_listeningSocket = -1;
		return;
	}

	if (!setNonBlocking(_listeningSocket)) {
		std::cerr << "Failed to set listening socket to non-blocking." << std::endl;
		close(_listeningSocket);
		_listeningSocket = -1;
		return;
	}

	_isRunning.store(true);
	_updateThread = std::thread(&Server::updateLoop, this);
	std::cout << "Server started on port " << p_port << "." << std::endl;
}

void Server::defineAction(const Message::Type& messageType, const std::function<void(long long& clientID, const Message& msg)>& action) {
	std::lock_guard<std::mutex> lock(_actionsMutex);
	_actions[messageType] = action;  // ✅ Déjà correct avec Message::Type
}

void Server::sendTo(const Message& message, long long clientID) {
	std::lock_guard<std::mutex> lock(_clientsMutex);
	auto it = _clients.find(clientID);
	if (it == _clients.end()) {
		std::cerr << "Client " << clientID << " not found." << std::endl;
		return;
	}
	int clientSocket = it->second;
	const std::vector<uint8_t>& full = message.getData();
	// If we have a session and it's encrypted, encrypt payload
	auto sit = _sessions.find(clientID);
	if (sit != _sessions.end() && sit->second.encrypted && full.size() >= Message::HEADER_SIZE) {
		uint32_t msgSizeNet;
		std::memcpy(&msgSizeNet, full.data() + sizeof(int), sizeof(uint32_t));
		uint32_t payload_size = ntohl(msgSizeNet);
		const unsigned char* payload = full.data() + Message::HEADER_SIZE;
		std::vector<unsigned char> cipher, tag;
		uint64_t counter = sit->second.send_counter;
		if (!ftcrypto::aes256gcm_encrypt(sit->second.key, counter, payload, payload_size, cipher, tag)) {
			std::cerr << "Server: encryption to client failed" << std::endl;
			return;
		}
		sit->second.send_counter++;

	uint32_t new_size = (uint32_t)(cipher.size() + tag.size());
	std::vector<unsigned char> out;
	out.resize(Message::HEADER_SIZE + new_size);
	std::memcpy(out.data(), full.data(), Message::HEADER_SIZE);
	// Message header size is stored in host byte order by Message::writeHeader
	std::memcpy(out.data() + sizeof(int), &new_size, sizeof(uint32_t));
		std::memcpy(out.data() + Message::HEADER_SIZE, cipher.data(), cipher.size());
		std::memcpy(out.data() + Message::HEADER_SIZE + cipher.size(), tag.data(), tag.size());
		size_t total = 0;
		while (total < out.size()) {
			ssize_t s = ::send(clientSocket, out.data() + total, out.size() - total, 0);
			if (s <= 0) { std::cerr << "send error: " << strerror(errno) << std::endl; return; }
			total += s;
		}
		return;
	}

	// plaintext send
	const std::vector<uint8_t>& data = message.getData();
	size_t totalSent = 0;
	while (totalSent < data.size()) {
		ssize_t sent = send(clientSocket, reinterpret_cast<const char*>(data.data() + totalSent), data.size() - totalSent, 0);
		if (sent <= 0) {
			std::cerr << "Failed to send message to client " << clientID << "." << std::endl;
			closeClient(clientID);
			return;
		}
		totalSent += sent;
	}
}

void Server::sendToArray(const Message& message, std::vector<long long> clientIDs) {
	for (long long clientID : clientIDs) {
		sendTo(message, clientID);
	}
}

void Server::sendToAll(const Message& message) {
	std::lock_guard<std::mutex> lock(_clientsMutex);
	for (const auto& pair : _clients) {
		sendTo(message, pair.first);
	}
}

void Server::update() {
    std::vector<std::pair<long long, Message>> toProc;
    {
        std::lock_guard<std::mutex> lock(_clientsMutex);
        toProc.swap(_pendingMessages);
        _pendingMessages.clear();
    }

    for (auto& process : toProc) {
        long long clientID = process.first;
        Message& msg = process.second;

        std::function<void(long long&, const Message&)> action;
        {
            std::lock_guard<std::mutex> lock(_actionsMutex);
            // ✅ FIX: Utiliser getType() au lieu de type() pour cohérence
            auto it = _actions.find(msg.getType());
            if (it != _actions.end()) {
                action = it->second;
            }
        }

        if (action) {
            action(clientID, msg);
			std::cout << "Processed message of type " << msg.getType() << " from client " << clientID << "." << std::endl;
        } else {
            std::cerr << "No action defined for message type " << msg.getType() << "." << std::endl;
        }
    }
}

void Server::stop() {
	if (!_isRunning.load()) {
		return;
	}

	_isRunning.store(false);
	if (_updateThread.joinable()) {
		_updateThread.join();
	}

	{
		std::lock_guard<std::mutex> lock(_clientsMutex);
		for (const auto& pair : _clients) {
			close(pair.second);
		}
		_clients.clear();
	}

	if (_listeningSocket >= 0) {
		close(_listeningSocket);
		_listeningSocket = -1;
	}

	std::cout << "Server stopped." << std::endl;
}

void Server::acceptNewClient() {
	sockaddr_in clientAddr;
	socklen_t clientAddrLen = sizeof(clientAddr);
	int clientSocket = accept(_listeningSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
	if (clientSocket < 0) {
		if (errno != EWOULDBLOCK && errno != EAGAIN) {
			std::cerr << "Failed to accept new client." << std::endl;
		}
		return;
	}

	if (!setNonBlocking(clientSocket)) {
		std::cerr << "Failed to set client socket to non-blocking." << std::endl;
		close(clientSocket);
		return;
	}

	long long clientID = _nextClientID++;
	{
		std::lock_guard<std::mutex> lock(_clientsMutex);
		_clients[clientID] = clientSocket;
	}
	std::cout << "New client connected with ID " << clientID << ". Performing handshake..." << std::endl;

	// Perform server-side handshake (blocking temporarily)
	int old_flags = fcntl(clientSocket, F_GETFL, 0);
	if (old_flags != -1) {
		fcntl(clientSocket, F_SETFL, old_flags & ~O_NONBLOCK); // set blocking
	}

	const std::string key_path = "server_key.pem";
	std::vector<unsigned char> server_priv, server_pub;
	if (!ftcrypto::load_private_key_pem(key_path, server_priv)) {
		// generate and save
		if (!ftcrypto::generate_x25519_keypair(server_pub, server_priv)) {
			std::cerr << "Server: failed to generate static keypair" << std::endl;
		} else {
			if (!ftcrypto::save_private_key_pem(key_path, server_priv)) {
				std::cerr << "Server: failed to save private key to " << key_path << std::endl;
			}
		}
	} else {
		if (!ftcrypto::raw_public_from_private(server_priv, server_pub)) {
			std::cerr << "Server: failed to compute public key from loaded private key" << std::endl;
		}
	}

	// send server public key (32 bytes)
	if (server_pub.size() == 32) {
		size_t sent = 0;
		while (sent < server_pub.size()) {
			ssize_t s = ::send(clientSocket, server_pub.data() + sent, server_pub.size() - sent, 0);
			if (s <= 0) { std::cerr << "Server: failed to send public key to client " << clientID << std::endl; break; }
			sent += s;
		}
	}

	// receive client public key (32 bytes)
	std::vector<unsigned char> client_pub(32);
	size_t rec = 0;
	while (rec < 32) {
		ssize_t r = ::recv(clientSocket, client_pub.data()+rec, 32-rec, 0);
		if (r <= 0) { std::cerr << "Server: failed to receive client public key for client " << clientID << std::endl; break; }
		rec += r;
	}

	if (server_priv.size() == 32 && rec == 32) {
		std::vector<unsigned char> shared;
		if (ftcrypto::derive_x25519_shared(server_priv, client_pub, shared)) {
			std::vector<unsigned char> key;
			if (ftcrypto::hkdf_sha256(shared, "matt-daemon session", key, 32)) {
				// store session
				Server::ClientSession sess;
				sess.encrypted = true;
				memcpy(sess.key, key.data(), 32);
				sess.send_counter = 1;
				sess.recv_counter = 1;
				{
					std::lock_guard<std::mutex> lock(_clientsMutex);
					_sessions[clientID] = sess;
				}
				std::cout << "Server: established encrypted session with client " << clientID << std::endl;
			}
		}
	}

	// restore non-blocking
	if (old_flags != -1) {
		fcntl(clientSocket, F_SETFL, old_flags);
	} else {
		setNonBlocking(clientSocket);
	}
}

bool Server::setNonBlocking(int socket) {
	int flags = fcntl(socket, F_GETFL, 0);
	if (flags == -1) {
		return false;
	}
	if (fcntl(socket, F_SETFL, flags | O_NONBLOCK) == -1) {
		return false;
	}
	return true;
}

void Server::receiveFromClient(long long clientID, int clientSocket) {
	uint8_t buffer[4096];
	ssize_t bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
	if (bytesRead > 0) {
		std::vector<uint8_t> data(buffer, buffer + bytesRead);
		size_t offset = 0;

		while (offset + Message::HEADER_SIZE <= data.size()) {
			int msgType;
			uint32_t msgSize;
			std::memcpy(&msgType, data.data() + offset, sizeof(int));
			std::memcpy(&msgSize, data.data() + offset + sizeof(int), sizeof(uint32_t));
			// Message::writeHeader writes size in host byte order, so use it directly

			if (offset + Message::HEADER_SIZE + msgSize > data.size()) {
				break;
			}
			Message msg;
			msg.setType(msgType);
			// Extract payload bytes
			std::vector<unsigned char> payload(data.data() + offset + Message::HEADER_SIZE, data.data() + offset + Message::HEADER_SIZE + msgSize);

			// Log raw payload (hex) and basic header info
			std::string raw_hex = hex_encode(payload.data(), payload.size());
			std::cout << "Server: received from client " << clientID << " type=" << msgType << " size=" << msgSize << " raw(hex)=";
			if (raw_hex.size() > 256) std::cout << raw_hex.substr(0,256) << "..." << std::endl; else std::cout << raw_hex << std::endl;

			// If session exists and is encrypted, decrypt payload expecting cipher+tag (tag 16 bytes)
			auto sit = _sessions.find(clientID);
			if (sit != _sessions.end() && sit->second.encrypted) {
				if (payload.size() < 16) {
					std::cerr << "Encrypted payload too small from client " << clientID << std::endl;
					offset += Message::HEADER_SIZE + msgSize;
					continue;
				}
				size_t taglen = 16;
				size_t cipherlen = payload.size() - taglen;
				std::vector<unsigned char> plain;
				bool decrypted = ftcrypto::aes256gcm_decrypt(sit->second.key, sit->second.recv_counter, payload.data(), cipherlen, payload.data() + cipherlen, taglen, plain);
				if (!decrypted) {
					std::cerr << "Failed to decrypt message from client " << clientID << ". Treating payload as plaintext for logging." << std::endl;
					std::cerr << "Server: cipherlen=" << cipherlen << " taglen=" << taglen << std::endl;
					// Fall back: treat the received payload as plaintext (unverified)
					if (!payload.empty()) {
						if (is_printable_text(payload.data(), payload.size())) {
							std::string s((const char*)payload.data(), payload.size());
							std::cout << "Server (fallback plaintext): '" << s << "'" << std::endl;
						} else {
							std::string phex = hex_encode(payload.data(), payload.size());
							std::cout << "Server (fallback plaintext hex): " << (phex.size() > 256 ? phex.substr(0,256)+"..." : phex) << std::endl;
						}
					}
					msg.appendData(payload.data(), payload.size());
				} else {
					sit->second.recv_counter++;
					// Log decrypted plaintext (if printable show as text, otherwise show hex)
					if (!plain.empty()) {
						if (is_printable_text(plain.data(), plain.size())) {
							std::string s((const char*)plain.data(), plain.size());
							std::cout << "Server: decrypted payload from client " << clientID << ": '" << s << "'" << std::endl;
						} else {
							std::string phex = hex_encode(plain.data(), plain.size());
							std::cout << "Server: decrypted payload (hex) from client " << clientID << ": " << (phex.size() > 256 ? phex.substr(0,256)+"..." : phex) << std::endl;
						}
					} else {
						std::cout << "Server: decrypted payload empty from client " << clientID << std::endl;
					}
					msg.appendData(plain.data(), plain.size());
				}
			} else {
				// plaintext path: log content
				if (!payload.empty()) {
					if (is_printable_text(payload.data(), payload.size())) {
						std::string s((const char*)payload.data(), payload.size());
						std::cout << "Server: plaintext payload from client " << clientID << ": '" << s << "'" << std::endl;
					} else {
						std::string phex = hex_encode(payload.data(), payload.size());
						std::cout << "Server: plaintext payload (hex) from client " << clientID << ": " << (phex.size() > 256 ? phex.substr(0,256)+"..." : phex) << std::endl;
					}
				}
				msg.appendData(payload.data(), payload.size());
			}

			{
				std::lock_guard<std::mutex> lock(_clientsMutex);
				_pendingMessages.emplace_back(clientID, msg);
			}
			offset += Message::HEADER_SIZE + msgSize;
		}
	} else if (bytesRead == 0) {
		std::cout << "Client " << clientID << " disconnected." << std::endl;
		closeClient(clientID);
	} else {
		if (errno != EWOULDBLOCK && errno != EAGAIN) {
			std::cerr << "Failed to receive data from client " << clientID << "." << std::endl;
			closeClient(clientID);
		}
	}
}

void Server::updateLoop() {
	while (_isRunning.load()) {
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(_listeningSocket, &readfds);
		int maxfd = _listeningSocket;

		{
			std::lock_guard<std::mutex> lock(_clientsMutex);
			for (const auto& pair : _clients) {
				FD_SET(pair.second, &readfds);
				if (pair.second > maxfd) {
					maxfd = pair.second;
				}
			}
		}

		timeval timeout;
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		int activity = select(maxfd + 1, &readfds, nullptr, nullptr, &timeout);
		if (activity < 0) {
			if (errno != EINTR) {
				std::cerr << "Select error." << std::endl;
			}
			continue;
		}

		if (FD_ISSET(_listeningSocket, &readfds)) {
			acceptNewClient();
		}

		std::vector<long long> clientsToReceive;
		{
			std::lock_guard<std::mutex> lock(_clientsMutex);
			for (const auto& pair : _clients) {
				if (FD_ISSET(pair.second, &readfds)) {
					clientsToReceive.push_back(pair.first);
				}
			}
		}

		for (long long clientID : clientsToReceive) {
			int clientSocket;
			{
				std::lock_guard<std::mutex> lock(_clientsMutex);
				auto it = _clients.find(clientID);
				if (it != _clients.end()) {
					clientSocket = it->second;
				} else {
					continue;
				}
			}
			receiveFromClient(clientID, clientSocket);
		}
	}
}

void Server::closeClient(long long clientID) {
	std::lock_guard<std::mutex> lock(_clientsMutex);
	auto it = _clients.find(clientID);
	if (it != _clients.end()) {
		close(it->second);
		_clients.erase(it);
		std::cout << "Closed connection with client " << clientID << "." << std::endl;
	}
}

