/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread.cpp                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/06 13:26:17 by hulefevr          #+#    #+#             */
/*   Updated: 2025/10/07 18:28:50 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/thread.hpp"

Thread::Thread(const std::string& name, std::function<void()> functToExecute)
	: _name(name), _functionToExecute(functToExecute), _thread(), _isRunning(false) {
	if (_functionToExecute == nullptr) {
		throw std::invalid_argument("Thread: function to execute cannot be null");
	}
}

Thread::~Thread() {
	if (_thread.joinable()) {
		_thread.join();
	}
}

void Thread::start() {
	if (_isRunning.load()) {
		throw std::runtime_error("Thread: thread is already running");
	}
	_isRunning.store(true);
	_thread = std::thread(&Thread::threadEntry, this);
}

void Thread::join() {
	if (_thread.joinable()) {
		_thread.join();
		_isRunning.store(false);
	}
}

bool Thread::isRunning() const {
	return _isRunning.load();
}

std::thread::id Thread::getId() const {
	return _thread.get_id();
}

std::string Thread::getName() const {
	return _name;
}

void Thread::threadEntry(Thread* threadInstance) {
	if (threadInstance && threadInstance->_functionToExecute) {
		threadInstance->_functionToExecute();
	}
	threadInstance->_isRunning.store(false);
}

void Thread::stop() {
	if (_isRunning.load()) {
		_isRunning.store(false);
		if (_thread.joinable()) {
			_thread.join();
		}
	}
}