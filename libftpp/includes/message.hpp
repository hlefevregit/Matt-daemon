/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   message.hpp                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/06 15:54:30 by hulefevr          #+#    #+#             */
/*   Updated: 2025/10/14 11:56:10 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include <vector>
#include <string>
#include <unordered_map>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <cstdio>
#include <cctype>
#include <cmath>
#include <chrono>
#include <arpa/inet.h>

class Message {
public:
    enum Type {
        UNKNOWN = 0,
        TEXT = 1,
        BINARY = 2,
        COMMAND = 3
    };

    static const size_t HEADER_SIZE = sizeof(int) + sizeof(uint32_t);
    static const size_t MAX_DATA_SIZE = 1024 * 1024; 
    Message();
    Message(int type);
    Message(Type type);
    ~Message();

    int type() const;
    Type getType();
    void setType(int type);
    void setType(Type type);
    int getType() const {return type();};

    const std::vector<uint8_t>& rawData() const;
    
    void clear();
    void resetData();
    
    template<typename T>
    Message& operator<<(const T& data) ;
    
    template<typename T>
    Message& operator>>(T& data) const;
    
    Message& operator<<(const std::string& data);
    Message& operator>>(std::string& data) const;

    void print() const;
    void printType() const;
    void printData() const;
    void printHex() const;
    void printAscii() const;
    void printBinary() const;

    std::string typeToString() const;
    std::string typeToString(int type) const;
    bool isValidType(int type) const;
    
    bool isTextMessage() const;
    bool isBinaryMessage() const;
    bool isCommandMessage() const;
    bool isEmpty() const;
    size_t getDataSize() const;
    void ensureCapacity(size_t size);
    void appendData(const uint8_t* data, size_t size);
    void extractData(uint8_t* data, size_t size);
    const std::vector<uint8_t>& getData() const { return _data; }

private:
    std::vector<uint8_t> _data;
    int _type;
    mutable size_t _readPos;

    static std::unordered_map<int, std::string> _typeToString;
    static std::unordered_map<std::string, int> _stringToType;
    static bool _typeMapsInitialized;

    void writeHeader();
    void readHeader();
    void checkReadBounds(size_t size) const;
    
    static const std::string& unknownTypeString();
    static void initTypeMaps();
    std::string intToString(int type) const;
    int stringToType(const std::string& str) const;
	void initTypeMapsOnce();
};

#include "message.tpp"