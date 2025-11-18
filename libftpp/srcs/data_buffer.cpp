/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   data_buffer.cpp                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/09/30 15:49:46 by hulefevr          #+#    #+#             */
/*   Updated: 2025/09/30 16:07:05 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "data_buffer.hpp"

DataBuffer::DataBuffer() : _readPos(0), _writePos(0) {
}

void DataBuffer::_clear() {
    _buffer.clear();
    _readPos = 0;
    _writePos = 0;
}

void DataBuffer::_reset() {
    _readPos = 0;
}

std::size_t DataBuffer::_size() const {
    return _buffer.size();
}

std::size_t DataBuffer::_capacity() const {
    return _buffer.capacity();	
}

DataBuffer& DataBuffer::operator<<(const std::string& str) {
    std::size_t strSize = str.size();
    if (_writePos + sizeof(std::size_t) + strSize > _buffer.size()) {
        _buffer.resize(_writePos + sizeof(std::size_t) + strSize);
    }
    
    std::memcpy(&_buffer[_writePos], &strSize, sizeof(std::size_t));
    _writePos += sizeof(std::size_t);
    
    std::memcpy(&_buffer[_writePos], str.data(), strSize);
    _writePos += strSize;
    
    return *this;
}

DataBuffer& DataBuffer::operator>>(std::string& str) {
    if (_readPos + sizeof(std::size_t) > _writePos) {
        throw std::runtime_error("Not enough data in buffer to read string size");
    }
    
    std::size_t strSize;
    std::memcpy(&strSize, &_buffer[_readPos], sizeof(std::size_t));
    _readPos += sizeof(std::size_t);
    
    if (_readPos + strSize > _writePos) {
        throw std::runtime_error("Not enough data in buffer to read string data");
    }
    
    str.assign(reinterpret_cast<char*>(&_buffer[_readPos]), strSize);
    _readPos += strSize;
    
    return *this;
}




