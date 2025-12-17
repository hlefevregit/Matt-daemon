/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread_safe_queue.tpp                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/06 13:18:53 by hulefevr          #+#    #+#             */
/*   Updated: 2025/10/06 13:23:11 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include "thread_safe_queue.hpp"

template<typename TType>
ThreadSafeQueue<TType>::ThreadSafeQueue() : _queue() {}

template<typename TType>
ThreadSafeQueue<TType>::~ThreadSafeQueue() {
	clear();
}

template<typename TType>
void ThreadSafeQueue<TType>::push_back(const TType& newElement) {
	std::lock_guard<std::mutex> lock(_mutex);
	_queue.push_back(newElement);
}

template<typename TType>
void ThreadSafeQueue<TType>::push_front(const TType& newElement) {
	std::lock_guard<std::mutex> lock(_mutex);
	_queue.push_front(newElement);
}

template<typename TType>
TType ThreadSafeQueue<TType>::pop_back() {
	std::lock_guard<std::mutex> lock (_mutex);
	if (_queue.empty()) {
		throw std::runtime_error("ThreadSafeQueue: pop_back from empty queue");
	}
	TType element = _queue.back();
	_queue.pop_back();
	return element;
}

template<typename TType>
TType ThreadSafeQueue<TType>::pop_front() {
	std::lock_guard<std::mutex> lock(_mutex);
	if (_queue.empty()) {
		throw std::runtime_error("ThreadSafeQueue: pop_front from empty queue");
	}
	TType element = _queue.front();
	_queue.pop_front();
	return element;
}

template<typename TType>
size_t ThreadSafeQueue<TType>::size() const {
	std::lock_guard<std::mutex> lock(_mutex);
	return _queue.size();
}

template<typename TType>
bool ThreadSafeQueue<TType>::empty() const {
	std::lock_guard<std::mutex> lock(_mutex);
	return _queue.empty();
}

template<typename TType>
void ThreadSafeQueue<TType>::clear() {
	std::lock_guard<std::mutex> lock(_mutex);
	_queue.clear();
}
