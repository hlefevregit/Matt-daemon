#include "../include/Signal_handler.hpp"
#include "../include/Tintin_reporter.hpp"
#include "../include/Matt_daemon.hpp"

volatile sig_atomic_t   Signal_handler::g_quit = 0;
volatile sig_atomic_t   Signal_handler::g_lastSignal = 0;
Tintin_reporter         *Signal_handler::g_reporter = NULL;
Matt_daemon              *Signal_handler::g_daemon = NULL;

void    Signal_handler::setup( Tintin_reporter *reporter, Matt_daemon *daemon )
{
    g_reporter = reporter;
    g_daemon = daemon;

    struct sigaction sa{};
    sa.sa_handler = &Signal_handler::handle;
    sigemptyset( &sa.sa_mask );
    sa.sa_flags = 0;

    sigaction( SIGINT, &sa, NULL );
    sigaction( SIGTERM, &sa, NULL );
    sigaction( SIGQUIT, &sa, NULL );

    signal(SIGPIPE, SIG_IGN);
}

void Signal_handler::handle( int signum )
{
    g_lastSignal = signum;
    g_quit = 1;
}

Matt_daemon*    Signal_handler::daemon() { return g_daemon; }

bool    Signal_handler::shouldQuit() { return (g_quit != 0); }

void    Signal_handler::requestQuit() { g_quit = 1; }

int Signal_handler::lastSignal()
{
    return static_cast<int>(g_lastSignal);
}