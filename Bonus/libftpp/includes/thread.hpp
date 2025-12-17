/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread.hpp                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/06 13:23:54 by hulefevr          #+#    #+#             */
/*   Updated: 2025/10/07 18:28:35 by hulefevr         ###   ########.fr       */
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