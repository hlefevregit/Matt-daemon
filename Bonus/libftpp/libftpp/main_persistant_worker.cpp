#include "threading.hpp"
#include "thread_safe_iostream.hpp"
#include "../includes/persistant_worker.hpp"
#include <iostream>

int main() {
    PersistentWorker worker;

    ThreadSafeIOStream ios;

    auto task1 = [&ios]() {
        ios << "Executing Task 1" << std::endl;
    };

    auto task2 = [&ios]() {
        ios << "Executing Task 2" << std::endl;
    };

    worker.addTask("Task1", task1);
    worker.addTask("Task2", task2);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    worker.removeTask("Task1");

    std::this_thread::sleep_for(std::chrono::seconds(1));

    return 0;
}

