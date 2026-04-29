#include "fs.h"
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <stdexcept>
#include <sodium.h>

static const char MAGIC[] = "LPASS01";

static std::string dir() { return std::string(getenv("HOME")) + "/.logpas"; }
static std::string vault() { return dir() + "/vault.enc"; }
static std::string tempf() { return dir() + "/vault.tmp"; }

void ensure_storage() { mkdir(dir().c_str(), 0700); }

std::vector<unsigned char> make_salt() {
    std::vector<unsigned char> salt(16);
    randombytes_buf(salt.data(), salt.size());
    return salt;
}

bool write_vault(const std::vector<unsigned char>& salt,
                 const std::vector<unsigned char>& nonce,
                 const std::vector<unsigned char>& tag,
                 const std::vector<unsigned char>& cipher) {
    ensure_storage();

    if (access(vault().c_str(), F_OK) == 0)
        rename(vault().c_str(), (vault() + ".bak").c_str());

    int fd = open(tempf().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) throw std::runtime_error("cannot open temp vault");

    flock(fd, LOCK_EX);

    
    if (::write(fd, MAGIC, 7) == -1)
        throw std::runtime_error("write MAGIC failed");
    if (::write(fd, salt.data(), salt.size()) == -1)
        throw std::runtime_error("write salt failed");
    if (::write(fd, nonce.data(), nonce.size()) == -1)
        throw std::runtime_error("write nonce failed");
    if (::write(fd, tag.data(), tag.size()) == -1)
        throw std::runtime_error("write tag failed");
    if (::write(fd, cipher.data(), cipher.size()) == -1)
        throw std::runtime_error("write cipher failed");

    fsync(fd);
    fchmod(fd, 0600);

    flock(fd, LOCK_UN);
    close(fd);

    if (rename(tempf().c_str(), vault().c_str()) != 0)
        throw std::runtime_error("rename failed");

    return true;
}

bool read_vault(std::vector<unsigned char>& salt,
                std::vector<unsigned char>& nonce,
                std::vector<unsigned char>& tag,
                std::vector<unsigned char>& cipher) {
    int fd = open(vault().c_str(), O_RDONLY);
    if (fd < 0) return false;

    flock(fd, LOCK_SH);

    char magic[7];
    if (::read(fd, magic, 7) != 7 || std::memcmp(magic, MAGIC, 7) != 0) {
        flock(fd, LOCK_UN);
        close(fd);
        throw std::runtime_error("invalid vault format");
    }

    salt.resize(16);
    nonce.resize(12);
    tag.resize(16);

    if (::read(fd, salt.data(), 16) == -1)
        throw std::runtime_error("read salt failed");
    if (::read(fd, nonce.data(), 12) == -1)
        throw std::runtime_error("read nonce failed");
    if (::read(fd, tag.data(), 16) == -1)
        throw std::runtime_error("read tag failed");

    char buf[4096];
    int n;
    while ((n = ::read(fd, buf, sizeof(buf))) > 0)
        cipher.insert(cipher.end(), buf, buf + n);

    flock(fd, LOCK_UN);
    close(fd);
    return true;
}
