/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   data_buffer.hpp                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hugo <hugo@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/09/30 15:49:28 by hulefevr          #+#    #+#             */
/*   Updated: 2025/12/17 17:39:59 by hugo             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include <vector>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <type_traits>

class DataBuffer {
public:
	DataBuffer();

	// Value-like buffer: allow default copy/move behavior
	DataBuffer(const DataBuffer&) = default;
	DataBuffer& operator=(const DataBuffer&) = default;
	DataBuffer(DataBuffer&&) = default;
	DataBuffer& operator=(DataBuffer&&) = default;
	
	void _clear();
	void _reset();

	std::size_t _size() const;
	std::size_t _capacity() const;

	DataBuffer& operator<<(const std::string& str);
	DataBuffer& operator>>(std::string& str);
	
	template <typename TType>
	DataBuffer& operator<<(const TType& data);
	
	template <typename TType>
	DataBuffer& operator>>(TType& data);

private:
	std::vector<unsigned char> _buffer;
	std::size_t _readPos;
	std::size_t _writePos;
	
};

#include "data_buffer.tpp"