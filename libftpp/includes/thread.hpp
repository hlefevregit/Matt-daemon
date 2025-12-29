/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread.hpp                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hugo <hugo@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/06 13:23:54 by hulefevr          #+#    #+#             */
/*   Updated: 2025/12/17 17:39:58 by hugo             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include <thread>
#include <string>
#include <functional>
#include <atomic>


#include "thread_safe_iostream.hpp"

class Thread {
public:
	Thread(const std::string& name, std::function<void()> functToExecute);
	~Thread();

	// Thread wraps std::thread and should not be copyable/movable implicitly
	Thread(const Thread&) = delete;
	Thread& operator=(const Thread&) = delete;
	Thread(Thread&&) = delete;
	Thread& operator=(Thread&&) = delete;

	void start();
	void join();
	bool isRunning() const;
	std::thread::id getId() const;
	std::string getName() const;
	void stop();

private:
	std::string _name;
	std::function<void()> _functionToExecute;
	std::thread _thread;
	std::atomic<bool> _isRunning;
	
	static void threadEntry(Thread* threadInstance);

};