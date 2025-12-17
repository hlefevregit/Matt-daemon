/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   message.tpp                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/06 16:00:02 by hulefevr          #+#    #+#             */
/*   Updated: 2025/10/10 13:05:09 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include "message.hpp"

template<typename T>
Message& Message::operator<<(const T& data) {
	size_t dataSize = sizeof(T);
	if (getDataSize() + dataSize > MAX_DATA_SIZE) {
		throw std::runtime_error("Message data size exceeds maximum limit");
	}
	size_t oldSize = _data.size();
	_data.resize(oldSize + dataSize);
	std::memcpy(&_data[oldSize], &data, dataSize);
	writeHeader();
	return *this;
}

template<typename T>
Message& Message::operator>>(T& data) const {
    checkReadBounds(sizeof(T));
    std::memcpy(&data, &_data[_readPos], sizeof(T));
    _readPos += sizeof(T);
    return const_cast<Message&>(*this);
}

