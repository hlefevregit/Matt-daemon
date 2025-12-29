#ifndef MATT_DAEMON_HPP
# define MATT_DAEMON_HPP

# include "Tintin_reporter.hpp"
# include "Signal_handler.hpp"

class Server;

class Matt_daemon
{
    public:
        Matt_daemon();
        ~Matt_daemon();

        void    start();
        void    requestShutdown( const std::string &reason );
        bool    isShuttingdown( ) const;

    private:
        int                 _lockFd;
        Tintin_reporter     *_md_reporter;
        Server              *_server;
        bool                _isDaemonized = false;
        bool                _shuttingdown = false;

        std::string  signalToString(int sig) const;

        void    checkRoot();
        void    createDirsAndLogFile();
        void    createLockFile();
        void    removeLockFile();
        void    daemonize();
        void    setupSignals();
        void    run();

        Matt_daemon( const Matt_daemon& );
        Matt_daemon&    operator=( const Matt_daemon& );
};

#endif