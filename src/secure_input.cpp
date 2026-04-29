#include "secure_input.h"
#include <termios.h>
#include <unistd.h>
#include <iostream>

std::string read_password() {
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::string pwd;
    std::getline(std::cin, pwd);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
    return pwd;
}
