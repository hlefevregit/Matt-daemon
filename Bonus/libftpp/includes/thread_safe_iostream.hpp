/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread_safe_iostream.hpp                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/06 12:00:47 by hulefevr          #+#    #+#             */
/*   Updated: 2025/10/06 12:06:29 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

class ThreadSafeIOStream {
public:
	ThreadSafeIOStream();

	void setPrefix(const std::string& prefix);
	
	template<typename T>
	void prompt(const std::string& question, T& dest);

	template<typename T>
	ThreadSafeIOStream& operator<<(const T& data);
	
	// Overload for std::endl and other manipulators
	ThreadSafeIOStream& operator<<(std::ostream& (*manip)(std::ostream&));

	template<typename T>
	ThreadSafeIOStream& operator>>(T& dest);
private:
	static std::mutex _iMutex;
	static std::mutex _oMutex;
	
	thread_local static std::string _prefix;
	thread_local static bool _isNewLine;

	void _printPrefix();
	
};

#include "thread_safe_iostream.tpp"