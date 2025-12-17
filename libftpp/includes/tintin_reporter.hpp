/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tintin_reporter.hpp                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   Created: 2025/12/17 by assistant                     +#+  +:+       +#+        */
/*                                                    +#+  +:+       +#+        */
/* ************************************************************************** */

#pragma once

#include <string>
#include <fstream>
#include <mutex>

class Tintin_reporter {
public:
    // Get the singleton instance
    static Tintin_reporter& instance();

    // Initialize reporter with a logfile path. Safe to call multiple times.
    void init(const std::string& logfile_path);

    // Log a message (will be prefixed with timestamp).
    void log(const std::string& message);

private:
    Tintin_reporter();
    ~Tintin_reporter();

    // singleton must not be copyable or movable
    Tintin_reporter(const Tintin_reporter&) = delete;
    Tintin_reporter& operator=(const Tintin_reporter&) = delete;
    Tintin_reporter(Tintin_reporter&&) = delete;
    Tintin_reporter& operator=(Tintin_reporter&&) = delete;

    std::mutex _mutex;
    std::ofstream _ofs;
    std::string _path;
    bool _initialized;
};
