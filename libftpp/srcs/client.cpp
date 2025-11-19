/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   client.cpp                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hugo <hugo@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/08 11:29:41 by hulefevr          #+#    #+#             */
/*   Updated: 2025/11/19 15:23:57 by hugo             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/network.hpp"
#include "../includes/threading.hpp"
#include "../includes/crypto.hpp"


Client::Client(int socket_fd, const std::string& ip_address, uint16_t port)
	: _socket_fd(socket_fd), _ip_address(ip_address), _port(port), _connected(false),
	  _recv_buffer(), _send_mutex(), _recv_mutex(), _recv_thread(), _stop_recv_thread(false) {
	if (socket_fd != -1)
		_connected = true;
}

Client::~Client() {
	disconnect();
}

int Client::getSocketFd() const {
	return _socket_fd;
}

std::string Client::getIpAddress() const {
	return _ip_address;
}

void Client::connect(const std::string& address, const size_t& port) {
	if (_connected) {
		std::cerr << "Client is already connected." << std::endl;
		return;
	}

	_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (_socket_fd == -1) {
		std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
		return;
	}

	sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	if (inet_pton(AF_INET, address.c_str(), &server_addr.sin_addr) <= 0) {
		std::cerr << "Invalid address: " << address << std::endl;
		close(_socket_fd);
		_socket_fd = -1;
		return;
	}

	if (::connect(_socket_fd, (sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
		std::cerr << "Connection failed: " << strerror(errno) << std::endl;
		close(_socket_fd);
		_socket_fd = -1;
		return;
	}

	_ip_address = address;
	_port = port;
	_connected = true;

	std::cout << "Client: socket created and connected to " << address << ":" << port << std::endl;

	// Perform lightweight X25519 handshake with server to derive session key
	// 1) receive server public key (32 bytes)
	std::vector<unsigned char> server_pub(32);
	size_t received = 0;
	std::cout << "Client: waiting for server public key (32 bytes)" << std::endl;
	while (received < 32) {
		ssize_t r = ::recv(_socket_fd, server_pub.data()+received, 32-received, 0);
		if (r < 0) {
			if (errno == EINTR) continue;
			std::cerr << "Failed to receive server public key: " << strerror(errno) << std::endl;
			break;
		} else if (r == 0) {
			std::cerr << "Server closed connection while sending public key" << std::endl;
			break;
		}
		received += r;
	}
	std::cout << "Client: received " << received << " bytes of server public key" << std::endl;

	// 2) generate client keypair and send client_pub
	std::vector<unsigned char> client_pub, client_priv;
	if (!ftcrypto::generate_x25519_keypair(client_pub, client_priv)) {
		std::cerr << "Failed to generate client keypair" << std::endl;
	} else {
		std::cout << "Client: generated keypair, sending client public key (" << client_pub.size() << " bytes)" << std::endl;
		ssize_t s = ::send(_socket_fd, client_pub.data(), client_pub.size(), 0);
		if (s != (ssize_t)client_pub.size()) {
			std::cerr << "Failed to send client public key" << std::endl;
		} else {
			// derive shared secret
			std::vector<unsigned char> shared;
			if (ftcrypto::derive_x25519_shared(client_priv, server_pub, shared)) {
				std::vector<unsigned char> key;
				if (ftcrypto::hkdf_sha256(shared, "matt-daemon session", key, 32)) {
					memcpy(_session_key, key.data(), 32);
					// Enable automatic encryption now that we re-enabled AES-GCM path.
					_encrypted = true;
					_send_counter = 1;
					_recv_counter = 1;
					std::cout << "Client: session key derived, encryption ENABLED" << std::endl;
				} else {
					std::cerr << "Client: HKDF failed" << std::endl;
				}
			} else {
				std::cerr << "Client: derive_x25519_shared failed" << std::endl;
			}
		}
	}

	_stop_recv_thread = false;
	_recv_thread = std::thread(&Client::recvLoop, this);
}


void Client::disconnect() {
	if (!_connected) {
		return;
	}

	_stop_recv_thread = true;
	if (_recv_thread.joinable()) {
		_recv_thread.join();
	}

	close(_socket_fd);
	_socket_fd = -1;
	_connected = false;
}

void Client::defineAction(const Message::Type& messageType, const std::function<void(const Message& msg)>& action) {
	_actions[messageType] = action;
}

void Client::send(const Message& message) {
	if (!_connected) {
		std::cerr << "Client is not connected. Cannot send message." << std::endl;
		return;
	}

	std::lock_guard<std::mutex> lock(_send_mutex);
	const std::vector<uint8_t>& full = message.rawData();

	// If encryption active and session key present, try to encrypt payload (bytes after header)
	if (_encrypted && full.size() >= Message::HEADER_SIZE) {
		// Defensive: ensure session key isn't all-zero (uninitialized)
		static unsigned char zero32[32] = {0};
		if (std::memcmp(_session_key, zero32, 32) != 0) {
	    int msg_type;
	    uint32_t msg_size_net;
	    std::memcpy(&msg_type, full.data(), sizeof(int));
	    std::memcpy(&msg_size_net, full.data() + sizeof(int), sizeof(uint32_t));
	    // Message::writeHeader stores size in host byte order. Keep it as-is.
	    uint32_t payload_size = msg_size_net;
	    // Debug: print raw header bytes to investigate incorrect payload lengths
	    fprintf(stderr, "Client::send header bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
		    full[0], full[1], full[2], full[3], full[4], full[5], full[6], full[7]);
			const unsigned char* payload = full.data() + Message::HEADER_SIZE;

			// encrypt payload
			std::vector<unsigned char> cipher;
			std::vector<unsigned char> tag;
			fprintf(stderr, "Client::send: encrypting payload_size=%u key0=%02x counter=%llu\n", payload_size, (unsigned char)_session_key[0], (unsigned long long)_send_counter);
			if (ftcrypto::aes256gcm_encrypt(_session_key, _send_counter, payload, payload_size, cipher, tag)) {
				_send_counter++;
				// build header with updated size = cipher + tag
				uint32_t new_size = (uint32_t)(cipher.size() + tag.size());
				std::vector<unsigned char> out;
				out.resize(Message::HEADER_SIZE + new_size);
				std::memcpy(out.data(), full.data(), Message::HEADER_SIZE);
				// Message header size is stored in host byte order by Message::writeHeader
				std::memcpy(out.data() + sizeof(int), &new_size, sizeof(uint32_t));
				// copy cipher then tag
				std::memcpy(out.data() + Message::HEADER_SIZE, cipher.data(), cipher.size());
				std::memcpy(out.data() + Message::HEADER_SIZE + cipher.size(), tag.data(), tag.size());
				// send out
				size_t total = 0;
				while (total < out.size()) {
					ssize_t s = ::send(_socket_fd, out.data() + total, out.size() - total, 0);
					if (s <= 0) { std::cerr << "send error: " << strerror(errno) << std::endl; return; }
					total += s;
				}
				return;
			} else {
				std::cerr << "Client::send: encryption failed, falling back to plaintext" << std::endl;
			}
		} else {
			std::cerr << "Client::send: session key appears uninitialized; sending plaintext fallback" << std::endl;
		}
	}

	// Non-encrypted send (fallback)
	const std::vector<uint8_t>& data = message.rawData();
	size_t total_sent = 0;
	while (total_sent < data.size()) {
		ssize_t sent = ::send(_socket_fd, data.data() + total_sent, data.size() - total_sent, 0);
		if (sent == -1) {
			std::cerr << "Failed to send message: " << strerror(errno) << std::endl;
			return;
		}
		total_sent += sent;
	}
}

void Client::update() {
	std::lock_guard<std::mutex> lock(_recv_mutex);
	while (true) {
		if (_recv_buffer.size() < Message::HEADER_SIZE) {
			break;
		}

		int msg_type;
		uint32_t msg_size;
		std::memcpy(&msg_type, _recv_buffer.data(), sizeof(int));
	std::memcpy(&msg_size, _recv_buffer.data() + sizeof(int), sizeof(uint32_t));
	// Message::writeHeader writes the size in host byte order. Keep it as-is.

		if (_recv_buffer.size() < Message::HEADER_SIZE + msg_size) {
			break;
		}

		Message message;
		message.clear(); // initialise header et readPos
		message.ensureCapacity(msg_size);
		message.appendData(_recv_buffer.data() + Message::HEADER_SIZE, msg_size);
		message.setType(msg_type); // écrit type + taille correcte dans l'en-tête
		handleMessage(message);

		_recv_buffer.erase(_recv_buffer.begin(), _recv_buffer.begin() + Message::HEADER_SIZE + msg_size);
	}
}

void Client::recvLoop() {
	while (!_stop_recv_thread) {
		uint8_t buffer[4096];
		ssize_t bytes_received = recv(_socket_fd, buffer, sizeof(buffer), 0);
		if (bytes_received > 0) {
			std::lock_guard<std::mutex> lock(_recv_mutex);
			_recv_buffer.insert(_recv_buffer.end(), buffer, buffer + bytes_received);
		} else if (bytes_received == 0) {
			std::cerr << "Server closed the connection." << std::endl;
			disconnect();
			break;
		} else {
			if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
				std::cerr << "Receive error: " << strerror(errno) << std::endl;
				disconnect();
				break;
			}
		}
	}
}

void Client::handleMessage(const Message& message) {
	auto it = _actions.find(static_cast<Message::Type>(message.getType()));
	if (it != _actions.end()) {
		it->second(message);
	} else {
		std::cerr << "No action defined for message type: " << message.typeToString() << std::endl;
	}
}


void Client::defineAction(int messageType, const std::function<void(const Message& msg)>& action) {
    _actions[static_cast<Message::Type>(messageType)] = action;
}

int Client::isUsernameAvailable(const std::string& username) {
	if (!_connected) {
		std::cerr << "Client is not connected. Cannot check username availability." << std::endl;
		return -1; // Indicate error
	}

	Message request(Message::Type::COMMAND);
	request << std::string("CHECK_USERNAME") << username;
	// Send this particular request in plaintext (bypass AES) to avoid handshake/timing issues
	{
		std::lock_guard<std::mutex> lock(_send_mutex);
		const std::vector<uint8_t>& data = request.rawData();
		size_t total_sent = 0;
		while (total_sent < data.size()) {
			ssize_t sent = ::send(_socket_fd, data.data() + total_sent, data.size() - total_sent, 0);
			if (sent == -1) {
				std::cerr << "Failed to send username check: " << strerror(errno) << std::endl;
				return -1;
			}
			total_sent += sent;
		}
	}

	// Wait for response (in a real implementation, this should be asynchronous)
	// Here we will just simulate waiting and checking the response
	std::this_thread::sleep_for(std::chrono::milliseconds(100));

	// In a real implementation, you would have a proper response handling mechanism
	// For this stub, we will assume the username is always available
	return 1; // 1 for available, 0 for taken
}
