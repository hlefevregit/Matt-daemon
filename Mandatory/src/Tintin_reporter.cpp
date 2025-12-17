#include "../include/Tintin_reporter.hpp"

Tintin_reporter::Tintin_reporter( const std::string &logFilePath )
{
    _ofs.open(logFilePath.c_str(), std::ios::out | std::ios::app );
    if (!_ofs.is_open())
    {
        std::cerr << "Tintin_reporter: couldn't open log file" << logFilePath << std::endl;
        std::exit(1);
    }
}

Tintin_reporter::~Tintin_reporter()
{
    if (_ofs.is_open())
        _ofs.close();
}

std::string Tintin_reporter::getTimestamp() const
{
    std::time_t t = std::time(NULL);
    std::tm     tm;
    localtime_r(&t,&tm);

    std::ostringstream oss;
    oss << "["
        << std::setfill('0') << std::setw(2) <<tm.tm_mday << "/"
        << std::setfill('0') << std::setw(2) <<(tm.tm_mon + 1) << "/"
        << tm.tm_year + 1900 << "-"
        << std::setfill('0') << std::setw(2) <<tm.tm_hour << ":"
        << std::setfill('0') << std::setw(2) <<tm.tm_min << ":"
        << std::setfill('0') << std::setw(2) <<tm.tm_sec
        << "]";
    return oss.str();
}

std::string Tintin_reporter::typeToString( LogType type ) const
{
    switch (type)
    {
        case INFO: return " [ INFO ] - Matt_daemon: ";
        case ERROR: return " [ ERROR ] - Matt_daemon: ";
        case LOG: return " [ LOG ] - ";
        default: return " [ INFO ] - Matt_daemon: ";
    }
}

void    Tintin_reporter::log( LogType type, const std::string &message )
{
    std::lock_guard<std::mutex>lock(_mutex);
    if (_ofs.is_open())
    {
        _ofs << getTimestamp()
             << typeToString( type )
             << message << std::endl;
    }
}

void    Tintin_reporter::info( const std::string &message )
{
    log( INFO, message );
}

void    Tintin_reporter::error( const std::string &message )
{
    log( ERROR, message );
}

void    Tintin_reporter::userLog( const std::string &message )
{
    log( LOG, message );
}