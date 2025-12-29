/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tintin_reporter.cpp                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   Created: 2025/12/17 by assistant                     +#+  +:+       +#+        */
/*                                                    +#+  +:+       +#+        */
/* ************************************************************************** */

#include "../includes/tintin_reporter.hpp"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>

Tintin_reporter& Tintin_reporter::instance() {
    static Tintin_reporter inst;
    return inst;
}

Tintin_reporter::Tintin_reporter() : _initialized(false) {}

Tintin_reporter::~Tintin_reporter() {
    std::lock_guard<std::mutex> lock(_mutex);
    if (_ofs.is_open()) _ofs.close();
}

void Tintin_reporter::init(const std::string& logfile_path) {
    std::lock_guard<std::mutex> lock(_mutex);
    if (_initialized && logfile_path == _path) return;

    // Ensure directory exists (best-effort)
    size_t pos = logfile_path.find_last_of('/');
    if (pos != std::string::npos) {
        std::string dir = logfile_path.substr(0, pos);
        mkdir(dir.c_str(), 0755);
    }

    // Create file with correct permissions if it doesn't exist
    int fd = ::open(logfile_path.c_str(), O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd >= 0) ::close(fd);

    if (_ofs.is_open()) _ofs.close();
    _ofs.open(logfile_path.c_str(), std::ios::app);
    if (!_ofs.is_open()) {
        // fallback: write to stderr
        std::cerr << "Tintin_reporter: failed to open logfile: " << logfile_path << std::endl;
        _initialized = false;
        return;
    }

    _path = logfile_path;
    _initialized = true;
}

void Tintin_reporter::log(const std::string& message) {
    std::lock_guard<std::mutex> lock(_mutex);
    // timestamp format: [ DD / MM / YYYY - HH : MM : SS]
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
#if defined(_MSC_VER)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    std::ostringstream oss;
    oss << "[ " << std::setfill('0') << std::setw(2) << tm.tm_mday << " / "
        << std::setfill('0') << std::setw(2) << (tm.tm_mon + 1) << " / "
        << (tm.tm_year + 1900) << " - "
        << std::setfill('0') << std::setw(2) << tm.tm_hour << " : "
        << std::setfill('0') << std::setw(2) << tm.tm_min << " : "
        << std::setfill('0') << std::setw(2) << tm.tm_sec << "] " << message << std::endl;

    if (_ofs.is_open()) {
        _ofs << oss.str();
        _ofs.flush();
    } else {
        // fallback to stderr
        std::cerr << oss.str();
    }
}
