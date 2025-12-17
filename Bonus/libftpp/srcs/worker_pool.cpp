/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   worker_pool.cpp                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/06 14:52:01 by hulefevr          #+#    #+#             */
/*   Updated: 2025/10/06 15:01:44 by hulefevr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/worker_pool.hpp"

WorkerPool::WorkerPool(size_t numWorkers) {
	_numWorkers = numWorkers;
	_stop = false;
	_activeJobs = 0;
	for (size_t i = 0; i < _numWorkers; i++) {
		_workers.emplace_back(&WorkerPool::workerThread, this);
	}
}

WorkerPool::~WorkerPool() {
	_stop = true;
	_condition.notify_all();
	for (std::thread &worker : _workers) {
		if (worker.joinable()) {
			worker.join();
		}
	}
}

void WorkerPool::addJob(const std::function<void()>& jobToExecute) {
	{
		std::lock_guard<std::mutex> lock(_jobsMutex);
		_jobs.push_back(jobToExecute);
	}
	_condition.notify_one();
}

void WorkerPool::workerThread() {
	while (true) {
		std::function<void()> job;
		{
			std::unique_lock<std::mutex> lock(_jobsMutex);
			_condition.wait(lock, [this] { return _stop || !_jobs.empty();});
			if (_stop && _jobs.empty()) {
				return;
			}
			job = _jobs.back();
			_jobs.pop_back();
			_activeJobs++;
		}
		job();
		_activeJobs--;	
	}
};

