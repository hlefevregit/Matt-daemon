#ifndef SERVER_HPP
# define SERVER_HPP

#include "includes.hpp"
#include "Tintin_reporter.hpp"

class Server
{
    public:
        explicit Server( Tintin_reporter& reporter );
        ~Server();

        bool    init( int port );
        void    shutdown();
        void    loopOnce();

    private:
        int                 _listenFd;
        Tintin_reporter     &_reporter;
        std::vector<int>    _clients;

        int     prepareFdSet(fd_set &readfds);
        int     waitForActivity(fd_set &readfds, int max_fd);
        void    handleNewConnection();
        void    handleClientMessage(fd_set &readfds);
        bool    processClientMessage(int fd);

        Server( const Server& );
        Server& operator=( const Server& );
};

#endif