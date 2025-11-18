/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   data_buffer.tpp                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/09/30 15:49:49 by hulefevr          #+#    #+#             */
/*   Updated: 2025/09/30 15:55:21 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef DATA_BUFFER_TPP
# define DATA_BUFFER_TPP

#include "data_buffer.hpp"

template <typename TType>
DataBuffer& DataBuffer::operator<<(const TType& data) {
	static_assert(std::is_trivially_copyable<TType>::value, "Data type must be trivially copyable");

	std::size_t dataSize = sizeof(TType);
	if (_writePos + dataSize > _buffer.size()) {
		_buffer.resize(_writePos + dataSize);
	}
	
	std::memcpy(&_buffer[_writePos], &data, dataSize);
	_writePos += dataSize;
	return *this;
}

template <typename TType>
DataBuffer& DataBuffer::operator>>(TType& data) {
	static_assert(std::is_trivially_copyable<TType>::value, "Data type must be trivially copyable");
	std::size_t dataSize = sizeof(TType);
	if (_readPos + dataSize > _writePos) {
		throw std::runtime_error("Not enough data in buffer to read");
	}
	std::memcpy(&data, &_buffer[_readPos], dataSize);
	_readPos += dataSize;
	return *this;
}

#endif