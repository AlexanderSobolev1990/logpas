#pragma once
#include <vector>
#include <string>

std::vector<unsigned char> derive_key(const std::string& pass,
                                      const std::vector<unsigned char>& salt);

std::vector<unsigned char> encrypt_data(const std::string& data,
                                        const std::vector<unsigned char>& key,
                                        std::vector<unsigned char>& nonce,
                                        std::vector<unsigned char>& tag);

std::string decrypt_data(const std::vector<unsigned char>& cipher,
                         const std::vector<unsigned char>& key,
                         const std::vector<unsigned char>& nonce,
                         const std::vector<unsigned char>& tag);
