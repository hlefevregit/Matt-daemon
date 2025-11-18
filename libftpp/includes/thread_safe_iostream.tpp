/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread_safe_iostream.tpp                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/06 12:01:18 by hulefevr          #+#    #+#             */
/*   Updated: 2025/10/06 12:07:15 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once
#include "thread_safe_iostream.hpp"

template<typename T>
void ThreadSafeIOStream::prompt(const std::string& question, T& dest) {
	std::lock_guard<std::mutex> lock(_iMutex);
	_printPrefix();
	std::cout << question;
	std::cin >> dest;
	_isNewLine = true;
}

template<typename T>
ThreadSafeIOStream& ThreadSafeIOStream::operator<<(const T& data) {
	std::lock_guard<std::mutex> lock(_oMutex);
	_printPrefix();
	std::cout << data;
	_isNewLine = false;
	return *this;
}

template<typename T>
ThreadSafeIOStream& ThreadSafeIOStream::operator>>(T& dest) {
	std::lock_guard<std::mutex> lock(_iMutex);
	std::cin >> dest;
	_isNewLine = true;
	return *this;
}

