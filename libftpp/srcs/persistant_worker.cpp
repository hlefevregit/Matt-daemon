/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   persistant_worker.cpp                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/06 15:19:29 by hulefevr          #+#    #+#             */
/*   Updated: 2025/10/07 18:27:20 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/persistant_worker.hpp"

PersistentWorker::PersistentWorker() {
	_stop = false;
	_activeTasks = 0;
	_sleepDuration = std::chrono::milliseconds(50);
	_worker = std::thread(&PersistentWorker::workerThread, this);
}

PersistentWorker::~PersistentWorker() {
	_stop = true;
	if (_worker.joinable()) {
		_worker.join();
	}
}

void PersistentWorker::addTask(const std::string& name, const std::function<void()>& jobToExecute) {
	std::lock_guard<std::mutex> lock(_tasksMutex);
	_tasks[name] = jobToExecute;
}

void PersistentWorker::removeTask(const std::string& name) {
	std::lock_guard<std::mutex> lock(_tasksMutex);
	_tasks.erase(name);
}

void PersistentWorker::workerThread() {
	while (!_stop.load()) {

		{
			std::lock_guard<std::mutex> lock(_tasksMutex);
			if (_stop.load()) {
				break;
			}
			for (auto it = _tasks.begin(); it != _tasks.end(); ++it) {
				if (_stop.load()) {
					break;
				}
				
				try {
					_activeTasks.fetch_add(1);
					it->second();
				} catch (const std::exception& e) {
					ThreadSafeIOStream tsio;
					tsio << "PersistentWorker: Exception in task '" << it->first << "': " << e.what() << std::endl;
				} catch (...) {
					ThreadSafeIOStream tsio;
					tsio << "PersistentWorker: Unknown exception in task '" << it->first << "'" << std::endl;
				}
				_activeTasks.fetch_sub(1);
			}
		}
		if (!_stop.load()) {
			std::this_thread::sleep_for(_sleepDuration);
		}
	}
	_activeTasks.store(0);
}