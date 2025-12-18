#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <cstring>
#include <cstdlib>
#include <string>
#include <cerrno>

#include "../libftpp/includes/network.hpp"
#include "../libftpp/includes/tintin_reporter.hpp"

static volatile sig_atomic_t g_quit = 0;
// lockfile info exposed for the signal handler (use only async-signal-safe calls)
static int g_lockfd = -1;
static const char* g_lockfile_cstr = "/var/lock/matt_daemon.lock";

static void handle_signal(int sig) {
	(void)sig;
	// try to clean up lockfile using async-signal-safe calls
	if (g_lockfd >= 0) {
		// close the fd (releases the flock held by this process)
		close(g_lockfd);
		g_lockfd = -1;
		// remove the lockfile entry
		unlink(g_lockfile_cstr);
	}
	g_quit = 1;
}

static void daemonize_process(const std::string &lockfile, const std::string &logfile, int &lockfd_out) {
	pid_t pid = fork();
	if (pid < 0) {
		std::cerr << "fork failed: " << strerror(errno) << std::endl;
		std::exit(1);
	}
	if (pid > 0) {
		// parent exits
		std::exit(0);
	}

	if (setsid() < 0) {
		std::cerr << "setsid failed: " << strerror(errno) << std::endl;
		std::exit(1);
	}

	pid = fork();
	if (pid < 0) {
		std::cerr << "second fork failed: " << strerror(errno) << std::endl;
		std::exit(1);
	}
	if (pid > 0) {
		std::exit(0);
	}

	umask(0);
	if (chdir("/") < 0) {
		std::cerr << "chdir / failed: " << strerror(errno) << std::endl;
	}

	// close std fds
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	// ensure log dir exists
	size_t pos = logfile.find_last_of('/');
	if (pos != std::string::npos) {
		std::string logdir = logfile.substr(0, pos);
		mkdir(logdir.c_str(), 0755);
	}

	// If a lockfd was already provided (pre-acquired before daemonizing),
	// reuse it. Otherwise open and lock the file here.
	int lockfd = lockfd_out;
	if (lockfd < 0) {
		lockfd = open(lockfile.c_str(), O_CREAT | O_RDWR, 0644);
		if (lockfd < 0) {
			// cannot log because fds closed; try to write to syslog or just exit
			_exit(1);
		}
		if (flock(lockfd, LOCK_EX | LOCK_NB) < 0) {
			// already running
			close(lockfd);
			_exit(1);
		}
	}

	// keep lockfd open for lifetime
	lockfd_out = lockfd;

	// redirect std fds to logfile
	int logfd = open(logfile.c_str(), O_CREAT | O_WRONLY | O_APPEND, 0644);
	if (logfd >= 0) {
		dup2(logfd, STDOUT_FILENO);
		dup2(logfd, STDERR_FILENO);
		// keep logfd open; it will be closed on exit
	}
}

int main() {
	// Ensure we run as root (needed to write under /var/... and to take the lock)
	if (geteuid() != 0) {
		std::cerr << "launch_serv must be run as root (use sudo). Exiting.\n";
		return 1;
	}

	// default locations
	const std::string lockfile = "/var/lock/matt_daemon.lock";
	const std::string logfile = "/var/log/matt_daemon/matt_daemon.log";

	// install simple signal handlers
	struct sigaction sa{};
	sa.sa_handler = handle_signal;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, nullptr);
	sigaction(SIGTERM, &sa, nullptr);
	sigaction(SIGQUIT, &sa, nullptr);
	signal(SIGPIPE, SIG_IGN);

	// create needed dirs (best-effort)
	mkdir("/var/log/matt_daemon", 0755);
	mkdir("/var/lock", 0755);

	int lockfd = -1;

	// Try to open and lock the lockfile before daemonizing so we can report
	// errors to the user if another instance is running or if the file cannot
	// be created/opened. Keep the descriptor open and pass it to the daemon
	// process so the lock is held for the lifetime of the daemon.
	int pre_lockfd = open(lockfile.c_str(), O_CREAT | O_RDWR, 0644);
	if (pre_lockfd < 0) {
		std::cerr << "Error: failed to create/open lockfile '" << lockfile << "': " << strerror(errno) << std::endl;
		return 1;
	}
	if (flock(pre_lockfd, LOCK_EX | LOCK_NB) < 0) {
		std::cerr << "Error: another instance may be running (failed to lock '" << lockfile << "'): " << strerror(errno) << std::endl;
		close(pre_lockfd);
		return 1;
	}

	// pass the pre-acquired lockfd into the daemonizer so the child keeps it
	lockfd = pre_lockfd;
	// expose to signal handler (will be inherited across fork)
	g_lockfd = pre_lockfd;
	daemonize_process(lockfile, logfile, lockfd);

	// now in daemon context
	// Initialize Tintin_reporter for structured daemon logging
	Tintin_reporter::instance().init(logfile);
	Tintin_reporter::instance().log(std::string("Daemon started. PID: ") + std::to_string(getpid()));

	Server server;
	server.start(4242);

	while (!g_quit) {
		server.update();
		usleep(10000);
	}

	if (lockfd >= 0) {
		flock(lockfd, LOCK_UN);
		close(lockfd);
		unlink(lockfile.c_str());
		g_lockfd = -1;
	}
	// cleanup
	server.stop();

	Tintin_reporter::instance().log("Daemon exiting");
	return 0;
}