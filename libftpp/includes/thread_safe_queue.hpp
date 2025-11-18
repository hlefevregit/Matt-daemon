/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread_safe_queue.hpp                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/06 13:13:58 by hulefevr          #+#    #+#             */
/*   Updated: 2025/10/06 13:18:48 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include <deque>
#include <mutex>
#include <stdexcept>

template<typename TType>
class ThreadSafeQueue {
public: 
	ThreadSafeQueue();
	~ThreadSafeQueue();

	void push_back(const TType& newElement);
	void push_front(const TType& newElement);
	TType pop_back();
	TType pop_front();
	
	size_t size() const;
	bool empty() const;
	void clear();
private:
	mutable std::mutex _mutex;
	std::deque<TType> _queue;
	
	ThreadSafeQueue(const ThreadSafeQueue& other) = delete;
	ThreadSafeQueue& operator=(const ThreadSafeQueue& other) = delete;
	
};

#include "thread_safe_queue.tpp"