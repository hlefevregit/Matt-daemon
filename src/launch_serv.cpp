#include <iostream>
#include "../libftpp/includes/network.hpp"
#include <csignal>

int main() {
	Server server;
	server.start(6668);
	while (true) {
		server.update();
	}
	return 0;
}