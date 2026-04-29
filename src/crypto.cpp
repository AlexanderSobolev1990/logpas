#include "crypto.h"
#include <openssl/evp.h>
#include <sodium.h>
#include <stdexcept>

std::vector<unsigned char> derive_key(const std::string& pass,
                                      const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(32);
    if (crypto_pwhash(key.data(), key.size(), pass.c_str(), pass.size(),
                      salt.data(),
                      crypto_pwhash_OPSLIMIT_MODERATE,
                      crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("key derivation failed");
    }
    return key;
}

std::vector<unsigned char> encrypt_data(const std::string& data,
                                        const std::vector<unsigned char>& key,
                                        std::vector<unsigned char>& nonce,
                                        std::vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    nonce.resize(12);
    tag.resize(16);
    randombytes_buf(nonce.data(), nonce.size());

    std::vector<unsigned char> out(data.size() + 16);
    int len = 0, total = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data());
    EVP_EncryptUpdate(ctx, out.data(), &len,
                      reinterpret_cast<const unsigned char*>(data.data()),
                      (int)data.size());
    total += len;
    EVP_EncryptFinal_ex(ctx, out.data() + total, &len);
    total += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    out.resize(total);
    return out;
}

std::string decrypt_data(const std::vector<unsigned char>& cipher,
                         const std::vector<unsigned char>& key,
                         const std::vector<unsigned char>& nonce,
                         const std::vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> out(cipher.size());
    int len = 0, total = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data());
    EVP_DecryptUpdate(ctx, out.data(), &len, cipher.data(), (int)cipher.size());
    total += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data());

    if (EVP_DecryptFinal_ex(ctx, out.data() + total, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("bad password or corrupted vault");
    }

    total += len;
    EVP_CIPHER_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(out.data()), total);
}
