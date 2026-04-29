#include "cli.h"
#include <sodium.h>
#include <csignal>
#include <cstdlib>

static void cleanup_handler(int) {
    std::_Exit(1);
}

int main(int argc, char** argv) {
    // sodium_init();

    std::signal(SIGINT, cleanup_handler);
    std::signal(SIGTERM, cleanup_handler);
    std::signal(SIGSEGV, cleanup_handler);

    return run_cli(argc, argv);
}
