#include "../include/Server.hpp"
#include "../include/Signal_handler.hpp"

Server::Server( Tintin_reporter& reporter ) : _listenFd(-1), _reporter( reporter ) {}

Server::~Server()
{
    shutdown();
}

bool    Server::init( int port )
{
    _listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (_listenFd < 0)
    {
        _reporter.error("socket() failed");
        return false;
    }

    int opt = 1;
    setsockopt(_listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(_listenFd, (sockaddr*)&addr, sizeof(addr)) < 0)
    {
        _reporter.error("bind() failed");
        ::close(_listenFd);
        _listenFd = -1;
        return false;
    }

    if (listen(_listenFd, 3) < 0)
    {
        _reporter.error("listen() failed");
        ::close(_listenFd);
        _listenFd = -1;
        return false;
    }

    return true;
}

void    Server::shutdown()
{
    for (size_t i = 0; i < _clients.size(); ++i)
        ::close(_clients[i]);
    _clients.clear();

    if (_listenFd >= 0)
    {
        ::close(_listenFd);
        _listenFd = -1;
    }
}

void    Server::loopOnce()
{
    if (_listenFd < 0)
        return;

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(_listenFd, &readfds);

    int max_fd = _listenFd;
    for (int fd : _clients)
    {
        FD_SET(fd, &readfds);
        if (fd > max_fd)
            max_fd = fd;
    }

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;

    int activity = select(max_fd + 1, &readfds, NULL, NULL, &tv);
    if (activity < 0 && errno != EINTR)
    {
        _reporter.error("select() error");
        return;
    }

    if (FD_ISSET(_listenFd, &readfds))
    {
        int client_fd = accept(_listenFd, NULL, NULL);
        if (client_fd < 0)
        {
            _reporter.error("accept() failed");
        }
        else if (_clients.size() >= 3)
        {
            std::string msg = "Server full. Only 3 clients allowed.\n";
            send(client_fd, msg.c_str(), msg.size(), MSG_NOSIGNAL);
            ::close(client_fd);
            _reporter.userLog("Connection refused: server full");
        }
        else
        {
            _clients.push_back(client_fd);
            _reporter.userLog("New connection");
        }
    }

    for (std::vector<int>::iterator it = _clients.begin(); it != _clients.end(); )
    {
        int fd = *it;
        std::vector<int>::iterator current = it;
        ++it;

        if (!FD_ISSET(fd, &readfds))
            continue;

        char buffer[1024];
        ssize_t bytes = recv(fd, buffer, sizeof(buffer) - 1, 0);

        if (bytes <= 0)
        {
            _reporter.userLog("Client disconnected");
            ::close(fd);
            _clients.erase(current);
            continue;
        }

        buffer[bytes] = '\0';
        std::string message(buffer);

        while (!message.empty() && (message.back() == '\n' || message.back() == '\r'))
            message.pop_back();

        if (message.empty())
            continue;

        _reporter.userLog(message);

        if (message == "quit")
        {
            _reporter.info("Request quit.");

            for (int client_fd : _clients)
            {
                ::close(client_fd);
            }
            _clients.clear();

            Signal_handler::requestQuit();
            return;
        }
    }
}