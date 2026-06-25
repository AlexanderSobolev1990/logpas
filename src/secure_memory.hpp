#pragma once

#include <sodium.h>

#include <string>
#include <vector>

inline void secure_clear(std::string& value) {
    if (!value.empty()) {
        sodium_memzero(&value[0], value.size());
        value.clear();
    }
}

inline void secure_clear(std::vector<unsigned char>& value) {
    if (!value.empty()) {
        sodium_memzero(value.data(), value.size());
        value.clear();
    }
}

class SecureStringGuard {
public:
    explicit SecureStringGuard(std::string& value) : value(value) {}

    ~SecureStringGuard() {
        secure_clear(value);
    }

    SecureStringGuard(const SecureStringGuard&) = delete;
    SecureStringGuard& operator=(const SecureStringGuard&) = delete;

private:
    std::string& value;
};

class SecureBufferGuard {
public:
    explicit SecureBufferGuard(std::vector<unsigned char>& value)
        : value(value) {}

    ~SecureBufferGuard() {
        secure_clear(value);
    }

    SecureBufferGuard(const SecureBufferGuard&) = delete;
    SecureBufferGuard& operator=(const SecureBufferGuard&) = delete;

private:
    std::vector<unsigned char>& value;
};
