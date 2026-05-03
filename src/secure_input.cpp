#include "secure_input.h"
#include <termios.h>
#include <unistd.h>
#include <iostream>
#include <stdexcept>

class TerminalEchoGuard {
public:
    TerminalEchoGuard() {
        if (!isatty(STDIN_FILENO)) {
            throw std::runtime_error("stdin is not a terminal");
        }

        if (tcgetattr(STDIN_FILENO, &old_term) != 0) {
            throw std::runtime_error("cannot read terminal attributes");
        }

        termios new_term = old_term;
        new_term.c_lflag &= ~ECHO;

        if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0) {
            throw std::runtime_error("cannot disable terminal echo");
        }

        echo_disabled = true;
    }

    ~TerminalEchoGuard() {
        if (echo_disabled) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        }
    }

    TerminalEchoGuard(const TerminalEchoGuard&) = delete;
    TerminalEchoGuard& operator=(const TerminalEchoGuard&) = delete;

private:
    termios old_term{};
    bool echo_disabled = false;
};

std::string read_password(const std::string& prompt) {
    TerminalEchoGuard echo_guard;

    std::cout << prompt << std::flush;

    std::string pwd;
    if (!std::getline(std::cin, pwd)) {
        throw std::runtime_error("cannot read password");
    }

    std::cout << std::endl;
    return pwd;
}
