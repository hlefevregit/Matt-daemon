/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   message.cpp                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/06 16:15:37 by hulefevr          #+#    #+#             */
/*   Updated: 2025/10/10 13:04:39 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/message.hpp"

std::unordered_map<int, std::string> Message::_typeToString;
std::unordered_map<std::string, int> Message::_stringToType;
bool Message::_typeMapsInitialized = false;


Message::Message() : _type(UNKNOWN), _readPos(0) {
	initTypeMapsOnce();
	writeHeader();
}

Message::Message(int type) : _type(type), _readPos(0) {
	initTypeMapsOnce();
	if (!isValidType(type)) {
		_type = UNKNOWN;
	}
	writeHeader();
}

Message::Message(Type type) : _type(static_cast<int>(type)), _readPos(0) {
	initTypeMapsOnce();
	writeHeader();
}

Message::~Message() {}

int Message::type() const {
	return _type;
}

Message::Type Message::getType() {
	return static_cast<Type>(_type);
}

void Message::setType(int type) {
	if (isValidType(type)) {
		_type = type;
	} else {
		_type = UNKNOWN;
	}
	writeHeader();
}

void Message::setType(Type type) {
	_type = static_cast<int>(type);
	writeHeader();
}

const std::vector<uint8_t>& Message::rawData() const {
	return _data;
}

void Message::clear() {
	_data.clear();
	_type = UNKNOWN;
	_readPos = 0;
	writeHeader();
}

void Message::resetData() {
	_data.resize(HEADER_SIZE);
	_readPos = HEADER_SIZE;
	writeHeader();
}

Message& Message::operator<<(const std::string& data) {
	uint32_t size = static_cast<uint32_t>(data.size());
	appendData(reinterpret_cast<const uint8_t*>(&size), sizeof(size));
	if (size > 0)
		appendData(reinterpret_cast<const uint8_t*>(data.data()), size);
	writeHeader();
	return *this;
}

Message& Message::operator>>(std::string& data) const {
    uint32_t size;
    *this >> size;  // Extract size first
    
    if (size > MAX_DATA_SIZE) {
        throw std::runtime_error("String size exceeds maximum allowed size");
    }
    
    checkReadBounds(size);
    data.resize(size);
    std::memcpy(&data[0], &_data[_readPos], size);
    _readPos += size;
    
    return const_cast<Message&>(*this);
}

void Message::print() const {
	printType();
	printData();
}

void Message::printType() const {
	std::cout << "Message Type: " << typeToString() << " (" << _type << ")\n";
}

void Message::printData() const {
	std::cout << "Message Data (" << getDataSize() << " bytes):\n";
	if (isTextMessage()) {
		printAscii();
	} else if (isBinaryMessage()) {
		printBinary();
	} else {
		printHex();
	}
}

void Message::printHex() const {
	for (size_t i = HEADER_SIZE; i < _data.size(); ++i) {
		printf("%02X ", _data[i]);
		if ((i - HEADER_SIZE + 1) % 16 == 0) {
			printf("\n");
		}
	}
	if ((_data.size() - HEADER_SIZE) % 16 != 0) {
		printf("\n");
	}
}

void Message::printAscii() const {
	for (size_t i = HEADER_SIZE; i < _data.size(); ++i) {
		char c = static_cast<char>(_data[i]);
		if (isprint(c)) {
			std::cout << c;
		} else {
			std::cout << '.';
		}
	}
	std::cout << std::endl;
}

void Message::printBinary() const {
	for (size_t i = HEADER_SIZE; i < _data.size(); ++i) {
		for (int bit = 7; bit >= 0; --bit) {
			std::cout << ((_data[i] >> bit) & 1);
		}
		std::cout << ' ';
		if ((i - HEADER_SIZE + 1) % 6 == 0) {
			std::cout << '\n';
		}
	}
	if ((_data.size() - HEADER_SIZE) % 6 != 0) {
		std::cout << '\n';
	}
}

std::string Message::typeToString() const {
	return intToString(_type);
}

std::string Message::typeToString(int type) const {
	return intToString(type);
}

bool Message::isValidType(int type) const {
    return (type >= UNKNOWN && type <= COMMAND);  // 0 <= type <= 3
}

bool Message::isTextMessage() const {
	return _type == TEXT;
}

bool Message::isBinaryMessage() const {
	return _type == BINARY;
}

bool Message::isCommandMessage() const {
	return _type == COMMAND;
}

bool Message::isEmpty() const {
	return getDataSize() == 0;
}

size_t Message::getDataSize() const {
	return _data.size() > HEADER_SIZE ? _data.size() - HEADER_SIZE : 0;
}

void Message::appendData(const uint8_t* data, size_t size) {
	if (size == 0) return;
	
	size_t oldSize = _data.size();
	_data.resize(oldSize + size);
	std::memcpy(&_data[oldSize], data, size);
}

void Message::extractData(uint8_t* data, size_t size) {
	std::copy(_data.begin() + _readPos, _data.begin() + _readPos + size, data);
	_readPos += size;
}

void Message::ensureCapacity(size_t size) {
	if (_data.size() + size > MAX_DATA_SIZE + HEADER_SIZE) {
		throw std::runtime_error("Message data exceeds maximum allowed size");
	}
}

void Message::writeHeader() {
    if (_data.size() < HEADER_SIZE) {
        _data.resize(HEADER_SIZE);
    }

    std::memcpy(&_data[0], &_type, sizeof(_type));
    
    uint32_t dataSize = static_cast<uint32_t>(_data.size() - HEADER_SIZE);
    std::memcpy(&_data[sizeof(_type)], &dataSize, sizeof(uint32_t));
    
    _readPos = HEADER_SIZE;
}
void Message::checkReadBounds(size_t size) const {
	if (_readPos + size > _data.size()) {
		throw std::runtime_error("Attempt to read beyond message data bounds");
	}
}

const std::string& Message::unknownTypeString() {
	static const std::string unknown = "UNKNOWN";
	return unknown;
}

void Message::initTypeMaps() {
	if (_typeMapsInitialized) return;

	_typeToString[UNKNOWN] = "UNKNOWN";
	_typeToString[TEXT] = "TEXT";
	_typeToString[BINARY] = "BINARY";
	_typeToString[COMMAND] = "COMMAND";

	for (const auto& pair : _typeToString) {
		_stringToType[pair.second] = pair.first;
	}

	_typeMapsInitialized = true;
}

std::string Message::intToString(int type) const {
    // Initialiser les maps si nécessaire (mais pas à chaque appel)
    if (!_typeMapsInitialized) {
        const_cast<Message*>(this)->initTypeMapsOnce();
    }
    
    auto it = _typeToString.find(type);
    if (it != _typeToString.end()) {
        return it->second;
    }
    return "UNKNOWN_TYPE_" + std::to_string(type);
}
int Message::stringToType(const std::string& str) const {
	initTypeMaps();
	auto it = _stringToType.find(str);
	if (it != _stringToType.end()) {
		return it->second;
	}
	return UNKNOWN;
}

void Message::initTypeMapsOnce() {
    if (_typeMapsInitialized) return;

    _typeToString[UNKNOWN] = "UNKNOWN";
    _typeToString[TEXT] = "TEXT";
    _typeToString[BINARY] = "BINARY";
    _typeToString[COMMAND] = "COMMAND";

    for (const auto& pair : _typeToString) {
        _stringToType[pair.second] = pair.first;
    }

    _typeMapsInitialized = true;
}