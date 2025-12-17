/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   worker_pool.hpp                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hulefevr <hulefevr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/06 14:51:42 by hulefevr          #+#    #+#             */
/*   Updated: 2025/10/06 14:55:43 by hulefevr         ###   ########.fr       */
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
	WorkerPool(const WorkerPool& other);
	WorkerPool& operator=(const WorkerPool& other);

	void workerThread();

	std::vector<std::thread> _workers;
	std::vector<std::function<void()>> _jobs;
	std::atomic<bool> _stop;
	std::mutex _jobsMutex;
	std::condition_variable _condition;
	std::atomic<size_t> _activeJobs;
	size_t _numWorkers;
	
};