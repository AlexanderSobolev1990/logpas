#include "fs.h"
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <stdexcept>
#include <string>
#include <sodium.h>

static const char MAGIC[] = "LPASS01";

std::string storage_dir() {
    const char* home = getenv("HOME");

    if (home == nullptr || home[0] == '\0') {
        throw std::runtime_error("HOME environment variable is not set");
    }

    return std::string(home) + "/.logpas";
}

static std::string vault() { return storage_dir() + "/vault.enc"; }
static std::string tempf() { return storage_dir() + "/vault.tmp"; }
static std::string lockf() { return storage_dir() + "/vault.lock"; }

class FileDescriptor {
public:
    explicit FileDescriptor(int fd = -1) : fd(fd) {}

    ~FileDescriptor() {
        if (fd >= 0) {
            close(fd);
        }
    }

    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;

    FileDescriptor(FileDescriptor&& other) noexcept : fd(other.fd) {
        other.fd = -1;
    }

    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this != &other) {
            if (fd >= 0) {
                close(fd);
            }

            fd = other.fd;
            other.fd = -1;
        }

        return *this;
    }

    int get() const { return fd; }

    int release() {
        int old = fd;
        fd = -1;
        return old;
    }

private:
    int fd;
};

static void close_checked(FileDescriptor& file, const char* message) {
    int fd = file.release();

    if (fd >= 0 && close(fd) != 0) {
        throw std::runtime_error(message);
    }
}

static void lock_file(int fd, int operation) {
    while (flock(fd, operation) != 0) {
        if (errno != EINTR) {
            throw std::runtime_error("cannot lock vault");
        }
    }
}

static FileDescriptor open_lock(int operation) {
    FileDescriptor lock_fd(open(lockf().c_str(), O_RDWR | O_CREAT, 0600));

    if (lock_fd.get() < 0) {
        throw std::runtime_error("cannot open vault lock");
    }

    lock_file(lock_fd.get(), operation);
    return lock_fd;
}

static void write_all(int fd, const void* data, size_t size,
                      const char* message) {
    const unsigned char* ptr = static_cast<const unsigned char*>(data);

    while (size > 0) {
        ssize_t n = ::write(fd, ptr, size);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }

            throw std::runtime_error(message);
        }

        if (n == 0) {
            throw std::runtime_error(message);
        }

        ptr += n;
        size -= static_cast<size_t>(n);
    }
}

static void read_exact(int fd, void* data, size_t size, const char* message) {
    unsigned char* ptr = static_cast<unsigned char*>(data);

    while (size > 0) {
        ssize_t n = ::read(fd, ptr, size);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }

            throw std::runtime_error(message);
        }

        if (n == 0) {
            throw std::runtime_error(message);
        }

        ptr += n;
        size -= static_cast<size_t>(n);
    }
}

static void fsync_dir() {
    FileDescriptor dir_fd(open(storage_dir().c_str(), O_RDONLY | O_DIRECTORY));

    if (dir_fd.get() < 0) {
        throw std::runtime_error("cannot open vault directory");
    }

    if (fsync(dir_fd.get()) != 0) {
        throw std::runtime_error("cannot sync vault directory");
    }
}

void ensure_storage() {
    const std::string dir = storage_dir();

    if (mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) {
        throw std::runtime_error("cannot create vault directory");
    }

    struct stat st {};

    if (stat(dir.c_str(), &st) != 0) {
        throw std::runtime_error("cannot stat vault directory");
    }

    if (!S_ISDIR(st.st_mode)) {
        throw std::runtime_error("vault path is not a directory");
    }

    if (chmod(dir.c_str(), 0700) != 0) {
        throw std::runtime_error("cannot chmod vault directory");
    }
}

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

    FileDescriptor lock_fd = open_lock(LOCK_EX);

    FileDescriptor fd(open(tempf().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600));

    if (fd.get() < 0) {
        throw std::runtime_error("cannot open temp vault");
    }

    write_all(fd.get(), MAGIC, 7, "write MAGIC failed");
    write_all(fd.get(), salt.data(), salt.size(), "write salt failed");
    write_all(fd.get(), nonce.data(), nonce.size(), "write nonce failed");
    write_all(fd.get(), tag.data(), tag.size(), "write tag failed");
    write_all(fd.get(), cipher.data(), cipher.size(), "write cipher failed");

    if (fchmod(fd.get(), 0600) != 0) {
        throw std::runtime_error("chmod temp vault failed");
    }

    if (fsync(fd.get()) != 0) {
        throw std::runtime_error("sync temp vault failed");
    }

    close_checked(fd, "close temp vault failed");

    const std::string vault_path = vault();
    const std::string backup_path = vault_path + ".bak";
    const bool had_vault = access(vault_path.c_str(), F_OK) == 0;

    if (had_vault && rename(vault_path.c_str(), backup_path.c_str()) != 0) {
        throw std::runtime_error("backup vault failed");
    }

    if (rename(tempf().c_str(), vault_path.c_str()) != 0) {
        if (had_vault) {
            rename(backup_path.c_str(), vault_path.c_str());
        }

        throw std::runtime_error("rename failed");
    }

    fsync_dir();

    lock_file(lock_fd.get(), LOCK_UN);

    return true;
}

bool read_vault(std::vector<unsigned char>& salt,
                std::vector<unsigned char>& nonce,
                std::vector<unsigned char>& tag,
                std::vector<unsigned char>& cipher) {
    ensure_storage();

    FileDescriptor lock_fd = open_lock(LOCK_SH);
    FileDescriptor fd(open(vault().c_str(), O_RDONLY));

    if (fd.get() < 0) {
        return false;
    }

    char magic[7];
    read_exact(fd.get(), magic, 7, "read MAGIC failed");

    if (std::memcmp(magic, MAGIC, 7) != 0) {
        throw std::runtime_error("invalid vault format");
    }

    salt.resize(16);
    nonce.resize(12);
    tag.resize(16);

    read_exact(fd.get(), salt.data(), 16, "read salt failed");
    read_exact(fd.get(), nonce.data(), 12, "read nonce failed");
    read_exact(fd.get(), tag.data(), 16, "read tag failed");

    char buf[4096];
    ssize_t n;

    while ((n = ::read(fd.get(), buf, sizeof(buf))) > 0) {
        cipher.insert(cipher.end(), buf, buf + n);
    }

    if (n < 0) {
        throw std::runtime_error("read cipher failed");
    }

    lock_file(lock_fd.get(), LOCK_UN);
    return true;
}
