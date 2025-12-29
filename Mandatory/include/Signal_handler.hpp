#ifndef SIGNAL_HANDLER_HPP
# define SIGNAL_HANDLER_HPP

# include "includes.hpp"

class Tintin_reporter;
class Matt_daemon;

class Signal_handler
{
    public:
        Signal_handler() = delete;
        ~Signal_handler() = delete;

        static void setup( Tintin_reporter *reporter, Matt_daemon *daemon );
        static bool shouldQuit();
        static void requestQuit();
        static int  lastSignal();
        static  Matt_daemon *daemon();

    private:
        static void handle( int signum );

        static volatile sig_atomic_t    g_quit;
        static volatile sig_atomic_t    g_lastSignal;
        static Tintin_reporter          *g_reporter;
        static Matt_daemon               *g_daemon;

        Signal_handler( const Signal_handler& );
        Signal_handler& operator=( const Signal_handler& );
};

#endif