/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   worker_pool.hpp                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hugo <hugo@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/06 14:51:42 by hulefevr          #+#    #+#             */
/*   Updated: 2025/12/17 17:40:03 by hugo             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include <thread>
#include <vector>
#include <functional>
#include <atomic>
#include <mutex>
#include <condition_variable>

class WorkerPool {
public:
	WorkerPool(size_t numWorkers);
	~WorkerPool();

	void addJob(const std::function<void()>& jobToExecute);
	
	class IJobs {
	public:
		virtual void execute() = 0;
	};

private:
	// non-copyable (owns worker threads)
	WorkerPool(const WorkerPool& other) = delete;
	WorkerPool& operator=(const WorkerPool& other) = delete;

	void workerThread();

	std::vector<std::thread> _workers;
	std::vector<std::function<void()>> _jobs;
	std::atomic<bool> _stop;
	std::mutex _jobsMutex;
	std::condition_variable _condition;
	std::atomic<size_t> _activeJobs;
	size_t _numWorkers;
	
};