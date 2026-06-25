#include "crypto.hpp"
#include "secure_memory.hpp"

#include <openssl/evp.h>
#include <sodium.h>
#include <limits>
#include <stdexcept>

class EvpCipherContext {
public:
    EvpCipherContext() : ctx(EVP_CIPHER_CTX_new()) {
        if (ctx == nullptr) {
            throw std::runtime_error("cannot create cipher context");
        }
    }

    ~EvpCipherContext() {
        EVP_CIPHER_CTX_free(ctx);
    }

    EvpCipherContext(const EvpCipherContext&) = delete;
    EvpCipherContext& operator=(const EvpCipherContext&) = delete;

    EVP_CIPHER_CTX* get() const { return ctx; }

private:
    EVP_CIPHER_CTX* ctx;
};

static void check_evp(int ok, const char* message) {
    if (ok != 1) {
        throw std::runtime_error(message);
    }
}

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
    if (data.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("input too large to encrypt");
    }

    EvpCipherContext ctx;
    nonce.resize(12);
    tag.resize(16);
    randombytes_buf(nonce.data(), nonce.size());

    std::vector<unsigned char> out(data.size() + 16);
    int len = 0, total = 0;

    check_evp(
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, NULL, NULL),
        "encrypt init failed"
    );
    check_evp(
        EVP_EncryptInit_ex(ctx.get(), NULL, NULL, key.data(), nonce.data()),
        "encrypt key setup failed"
    );
    check_evp(
        EVP_EncryptUpdate(
            ctx.get(),
            out.data(),
            &len,
            reinterpret_cast<const unsigned char*>(data.data()),
            static_cast<int>(data.size())
        ),
        "encrypt update failed"
    );
    total += len;
    check_evp(
        EVP_EncryptFinal_ex(ctx.get(), out.data() + total, &len),
        "encrypt final failed"
    );
    total += len;
    check_evp(
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data()),
        "encrypt tag failed"
    );

    out.resize(total);
    return out;
}

std::string decrypt_data(const std::vector<unsigned char>& cipher,
                         const std::vector<unsigned char>& key,
                         const std::vector<unsigned char>& nonce,
                         const std::vector<unsigned char>& tag) {
    if (cipher.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("input too large to decrypt");
    }

    EvpCipherContext ctx;
    std::vector<unsigned char> out(cipher.size());
    SecureBufferGuard out_guard(out);
    int len = 0, total = 0;

    check_evp(
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, NULL, NULL),
        "decrypt init failed"
    );
    check_evp(
        EVP_DecryptInit_ex(ctx.get(), NULL, NULL, key.data(), nonce.data()),
        "decrypt key setup failed"
    );
    check_evp(
        EVP_DecryptUpdate(
            ctx.get(),
            out.data(),
            &len,
            cipher.data(),
            static_cast<int>(cipher.size())
        ),
        "decrypt update failed"
    );
    total += len;

    check_evp(
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16,
                            const_cast<unsigned char*>(tag.data())),
        "decrypt tag setup failed"
    );

    if (EVP_DecryptFinal_ex(ctx.get(), out.data() + total, &len) <= 0) {
        throw std::runtime_error("bad password or corrupted vault");
    }

    total += len;

    std::string plain(reinterpret_cast<char*>(out.data()), total);
    secure_clear(out);
    return plain;
}
