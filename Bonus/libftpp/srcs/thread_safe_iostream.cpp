/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread_safe_iostream.cpp                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/06 12:01:15 by hulefevr          #+#    #+#             */
/*   Updated: 2025/10/06 12:08:31 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/thread_safe_iostream.hpp"

std::mutex ThreadSafeIOStream::_iMutex;
std::mutex ThreadSafeIOStream::_oMutex;
thread_local std::string ThreadSafeIOStream::_prefix = "";
thread_local bool ThreadSafeIOStream::_isNewLine = true;

ThreadSafeIOStream::ThreadSafeIOStream() {}

void ThreadSafeIOStream::setPrefix(const std::string& prefix) {
	_prefix = prefix;
}

void ThreadSafeIOStream::_printPrefix() {
	if (_isNewLine && !_prefix.empty()) {
		std::cout << _prefix;
		_isNewLine = false;
	}
}

ThreadSafeIOStream& ThreadSafeIOStream::operator<<(std::ostream& (*manip)(std::ostream&)) {
	std::lock_guard<std::mutex> lock(_oMutex);
	_printPrefix();
	std::cout << manip;
	_isNewLine = true;
	return *this;
}