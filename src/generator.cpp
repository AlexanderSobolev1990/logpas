#include "generator.h"
#include <sodium.h>

std::string generate_password(size_t len) {
    const char chars[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=";
    std::string out(len, ' ');
    for (size_t i = 0; i < len; ++i)
        out[i] = chars[randombytes_uniform(sizeof(chars) - 1)];
    return out;
}
