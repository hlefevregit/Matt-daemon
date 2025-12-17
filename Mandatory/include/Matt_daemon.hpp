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

    private:
        int                 _lockFd;
        Tintin_reporter     *_md_reporter;
        bool                _isDaemonized = false;
        Server              *_server;    

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