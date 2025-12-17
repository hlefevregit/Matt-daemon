#include "../include/Matt_daemon.hpp"
#include "../include/Signal_handler.hpp"
#include "../include/Server.hpp"

static const char *LOG_DIR = "/var/log/matt_daemon";
static const char *LOCK_DIR = "/var/lock";
static const char *LOG_FILE = "/var/log/matt_daemon/matt_daemon.log";
static const char *LOCK_FILE = "/var/lock/matt_daemon.lock";

Matt_daemon::Matt_daemon() : _lockFd(-1), _md_reporter(NULL), _server(NULL) {}

Matt_daemon::~Matt_daemon()
{
    if (_server)
        delete _server;
    if (_md_reporter)
        delete _md_reporter;
    removeLockFile();
}

void    Matt_daemon::checkRoot()
{
    if (geteuid() != 0)
    {
        std::cerr << "Error: Matt_daemon should be run as root." << std::endl;
        std::exit(1);
    }
}

void    Matt_daemon::createDirsAndLogFile()
{
    if (mkdir(LOG_DIR, 0755) == -1 && errno != EEXIST)
    {
        std::cerr << "Error: couldn't create " << LOG_DIR << std::endl;
        std::exit(1);
    }

    if (mkdir(LOCK_DIR, 0755) == -1 && errno != EEXIST)
    {
        std::cerr << "Error: couldn't create " << LOCK_DIR << std::endl;
        std::exit(1);
    }

    int fd = open(LOG_FILE, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0)
    {
        std::cerr << "Error: Couldn't create log file " << LOG_FILE << std::endl;
        std::exit(1);
    }
    close(fd);
}

void    Matt_daemon::createLockFile()
{
    _lockFd = open(LOCK_FILE, O_CREAT | O_RDWR, 0644);
    if (_lockFd < 0)
    {
        std::cerr << "Couldn't open " << LOCK_FILE << std::endl;
        std::exit(1);
    }

    if (flock(_lockFd, LOCK_EX | LOCK_NB) < 0)
    {
        std::cerr << "Another instance is already running (lock: " << LOCK_FILE << ")" << std::endl;

        if (_md_reporter)
            _md_reporter->error("Another instance is already running");

        close(_lockFd);
        _lockFd = -1;
        std::exit(1);
    }
}

void    Matt_daemon::removeLockFile()
{
    if (_lockFd >= 0)
    {
        flock(_lockFd, LOCK_UN);
        close(_lockFd);
        _lockFd = -1;
        unlink(LOCK_FILE);
    }
}

void    Matt_daemon::daemonize()
{
    pid_t pid = fork();

    if (pid < 0)
    {
        std::cerr << "Error: Fork failed." << std::endl;
        std::exit(1);
    }

    if (pid > 0)
        std::exit(0);

    if (setsid() < 0)
    {
        std::cerr << "Error: setsid failed." << std::endl;
        std::exit(1);
    }

    pid = fork();
    if (pid < 0)
    {
        std::cerr << "Error: Second fork failed." << std::endl;
        std::exit(1);
    }
    if (pid > 0)
        std::exit(0);

    _isDaemonized = true;

    umask(0);

    if (chdir("/") < 0)
    {
        std::cerr << "Error: chdir failed." << std::endl;
        std::exit(1);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

void    Matt_daemon::setupSignals()
{
    Signal_handler::setup(_md_reporter, this);
}

void    Matt_daemon::run()
{
    if (!_md_reporter)
        return;

    _server = new Server(*_md_reporter);

    if (!_server->init(4242))
    {
        _md_reporter->error("Failed to initialize server.");
        _exit(1);
    }

    _md_reporter->info("Server created.");
    _md_reporter->info("Entering Daemon mode.");
    _md_reporter->info("started. PID: " + std::to_string(getpid()));

    while (!Signal_handler::shouldQuit())
    {
        _server->loopOnce();
        usleep(10000);
    }

    _md_reporter->info("Quitting");
    _server->shutdown();
}

void    Matt_daemon::start()
{
    checkRoot();

    createDirsAndLogFile();
    _md_reporter = new Tintin_reporter(LOG_FILE);

    createLockFile();
    daemonize();

    _md_reporter->info("Started.");

    setupSignals();
    run();
}