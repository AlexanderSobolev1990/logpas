#include "cli.hpp"
#include <sodium.h>
#include <csignal>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <stdexcept>

static void cleanup_handler(int) {
    std::_Exit(1);
}

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "error: libsodium initialization failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::signal(SIGINT, cleanup_handler);
    std::signal(SIGTERM, cleanup_handler);
    std::signal(SIGSEGV, cleanup_handler);

    try {
        return run_cli(argc, argv);
    }
    catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "error: unknown error" << std::endl;
    }

    return EXIT_FAILURE;
}
