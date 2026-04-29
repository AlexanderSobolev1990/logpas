#pragma once
#include <vector>

void ensure_storage();
std::vector<unsigned char> make_salt();

bool write_vault(const std::vector<unsigned char>& salt,
                 const std::vector<unsigned char>& nonce,
                 const std::vector<unsigned char>& tag,
                 const std::vector<unsigned char>& cipher);

bool read_vault(std::vector<unsigned char>& salt,
                std::vector<unsigned char>& nonce,
                std::vector<unsigned char>& tag,
                std::vector<unsigned char>& cipher);
