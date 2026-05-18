#include "cli.h"
#include "vault.h"
#include "generator.h"
#include "clipboard.h"
#include "secure_input.h"
#include "secure_memory.h"
#include "fs.h"
#include "crypto.h"

#include <boost/program_options.hpp>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <sodium.h>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

static const int CLIPBOARD_KEY_CACHE_SECONDS = 60;
static const char KEY_CACHE_MAGIC[] = "LPKC01";

struct VaultFingerprint {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint64_t size = 0;
    std::int64_t mtime_sec = 0;
    std::int64_t mtime_nsec = 0;
    std::int64_t ctime_sec = 0;
    std::int64_t ctime_nsec = 0;
};

static std::string read_secret_twice(const std::string& prompt1,
                                     const std::string& prompt2) {
    std::string p1 = read_password(prompt1);
    std::string p2 = read_password(prompt2);
    SecureStringGuard p2_guard(p2);

    if (p1 != p2) {
        secure_clear(p1);
        throw std::runtime_error("password mismatch");
    }

    return p1;
}

static std::string vault_path() {
    return storage_dir() + "/vault.enc";
}

static std::string key_cache_path() {
    return storage_dir() + "/clipboard.key";
}

static std::string key_cache_temp_path() {
    return key_cache_path() + ".tmp." + std::to_string(getpid());
}

static bool write_all_fd(int fd, const void* data, size_t size) {
    const unsigned char* ptr = static_cast<const unsigned char*>(data);

    while (size > 0) {
        ssize_t n = write(fd, ptr, size);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }

            return false;
        }

        if (n == 0) {
            return false;
        }

        ptr += n;
        size -= static_cast<size_t>(n);
    }

    return true;
}

static bool read_all_fd(int fd, void* data, size_t size) {
    unsigned char* ptr = static_cast<unsigned char*>(data);

    while (size > 0) {
        ssize_t n = read(fd, ptr, size);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }

            return false;
        }

        if (n == 0) {
            return false;
        }

        ptr += n;
        size -= static_cast<size_t>(n);
    }

    return true;
}

static void clear_key_cache() {
    unlink(key_cache_path().c_str());
}

static bool vault_fingerprint(VaultFingerprint& fingerprint) {
    struct stat st {};

    if (stat(vault_path().c_str(), &st) != 0) {
        return false;
    }

    fingerprint.device = static_cast<std::uint64_t>(st.st_dev);
    fingerprint.inode = static_cast<std::uint64_t>(st.st_ino);
    fingerprint.size = static_cast<std::uint64_t>(st.st_size);
    fingerprint.mtime_sec = static_cast<std::int64_t>(st.st_mtim.tv_sec);
    fingerprint.mtime_nsec = static_cast<std::int64_t>(st.st_mtim.tv_nsec);
    fingerprint.ctime_sec = static_cast<std::int64_t>(st.st_ctim.tv_sec);
    fingerprint.ctime_nsec = static_cast<std::int64_t>(st.st_ctim.tv_nsec);
    return true;
}

static bool same_vault_fingerprint(const VaultFingerprint& a,
                                   const VaultFingerprint& b) {
    return a.device == b.device &&
           a.inode == b.inode &&
           a.size == b.size &&
           a.mtime_sec == b.mtime_sec &&
           a.mtime_nsec == b.mtime_nsec &&
           a.ctime_sec == b.ctime_sec &&
           a.ctime_nsec == b.ctime_nsec;
}

static bool load_cached_key(std::vector<unsigned char>& key) {
    const std::string path = key_cache_path();
    int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW);

    if (fd < 0) {
        return false;
    }

    struct stat st {};

    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != getuid() || (st.st_mode & 0077) != 0) {
        close(fd);
        clear_key_cache();
        return false;
    }

    char magic[6];
    std::int64_t expires = 0;
    VaultFingerprint cached_vault {};
    std::uint32_t key_size = 0;

    bool ok = read_all_fd(fd, magic, sizeof(magic)) &&
              read_all_fd(fd, &expires, sizeof(expires)) &&
              read_all_fd(fd, &cached_vault, sizeof(cached_vault)) &&
              read_all_fd(fd, &key_size, sizeof(key_size));

    if (ok && (std::memcmp(magic, KEY_CACHE_MAGIC, sizeof(magic)) != 0 ||
               key_size != crypto_aead_aes256gcm_KEYBYTES)) {
        ok = false;
    }

    if (ok) {
        key.assign(key_size, 0);
        ok = read_all_fd(fd, key.data(), key.size());
    }

    close(fd);

    VaultFingerprint current_vault {};
    const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));

    if (!ok || now >= expires || !vault_fingerprint(current_vault) ||
        !same_vault_fingerprint(current_vault, cached_vault)) {
        secure_clear(key);
        clear_key_cache();
        return false;
    }

    return true;
}

static void save_cached_key(const std::vector<unsigned char>& key) {
    VaultFingerprint current_vault {};

    if (!vault_fingerprint(current_vault)) {
        return;
    }

    const std::string path = key_cache_path();
    const std::string temp_path = key_cache_temp_path();

    unlink(temp_path.c_str());

    int fd = open(temp_path.c_str(),
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                  0600);

    if (fd < 0) {
        return;
    }

    const std::int64_t expires =
        static_cast<std::int64_t>(std::time(nullptr)) +
        CLIPBOARD_KEY_CACHE_SECONDS;
    const std::uint32_t key_size = static_cast<std::uint32_t>(key.size());

    bool ok = write_all_fd(fd, KEY_CACHE_MAGIC, 6) &&
              write_all_fd(fd, &expires, sizeof(expires)) &&
              write_all_fd(fd, &current_vault, sizeof(current_vault)) &&
              write_all_fd(fd, &key_size, sizeof(key_size)) &&
              write_all_fd(fd, key.data(), key.size());

    if (fchmod(fd, 0600) != 0) {
        ok = false;
    }

    if (close(fd) != 0) {
        ok = false;
    }

    if (ok && rename(temp_path.c_str(), path.c_str()) != 0) {
        ok = false;
    }

    if (!ok) {
        unlink(temp_path.c_str());
        clear_key_cache();
    }
}

int run_cli(int argc, char** argv) {
    namespace po = boost::program_options;

    po::options_description desc("Options", 220);    
    desc.add_options()
    (
        "help,h",
        "Show help"
    )
    (
        "add,a",
        po::value<std::vector<std::string>>()->multitoken(),
        "Add new 'site' and 'login', 'password' will be asked to print.\n"
        "Usage:\n"
        "   logpas -a <site> <login>"
    )
    (
        "show,s",
        po::value<std::string>(),
        "Show 'login' and 'password' for specified 'site'.\n"
        "Usage:\n"
        "   logpas -s <site>"
    )
    (
        "cp",
        po::value<std::string>(),
        "Copy 'password' for specified 'site' to clipboard.\n"
        "Note: clipboard will be cleared in 60 sec.\n"
        "Usage:\n"
        "   logpas --cp <site>"
    )
    (
        "cl",
        po::value<std::string>(),
        "Copy 'login' for specified 'site' to clipboard.\n"
        "Note: clipboard will be cleared in 60 sec.\n"
        "Usage:\n"
        "   logpas --cl <site>"
    )
    (   "search,r", 
        po::value<std::string>(), 
        "Search by 'site' field (partial match)"
    )
    (
        "delete",
        po::value<std::string>(),
        "DELETE 'site' record.\n"
        "Usage:\n"
        "   logpas --delete <site>"
    )
    (
        "update,u",
        po::value<std::vector<std::string>>()->multitoken(),
        "Update 'login' and 'password' for existing 'site', 'password' will be asked to print.\n"
        "Usage:\n"
        "   logpas -u <site> <login>"
    )
    (
        "decrypt,d",
        "Decrypt ~/.logpas/vault.enc and save it to ~/.logpas/vault.json"
    )
    (   "encrypt,e", 
        po::value<std::string>(), 
        "Encrypt specified JSON file to ~/.logpas/vault.enc with specifying new master-password.\n"
        "WARNING!!! Old vault.enc will be lost!"
    )
    (
        "all,l",
        "Show all records from ~/.logpas/vault.enc to terminal"
    )
    (
        "gen,g",
        po::value<int>(),
        "Generate password of specified length.\n"
        "Valid characters:\n"
        "   a-z A-Z 0-9 !@#$%^&*()_-+=\n"
        "Usage:\n"
        "   logpas -g <length>"
    );

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help") || argc == 1) {
        std::cout << desc << std::endl;
        return 0;
    }

    if (vm.count("gen")) {
        std::cout << generate_password(vm["gen"].as<int>()) << std::endl;
        return 0;
    }

    storage_dir();

    if (vm.count("encrypt")) {
        std::ifstream in(vm["encrypt"].as<std::string>());

        if (!in) {
            throw std::runtime_error("cannot open input file");
        }

        std::stringstream buffer;
        buffer << in.rdbuf();

        std::string json_data = buffer.str();
        SecureStringGuard json_guard(json_data);

        if (json_data.empty()) {
            throw std::runtime_error("input json file is empty");
        }

        try {
            std::stringstream validate_stream(json_data);

            boost::property_tree::ptree root;

            boost::property_tree::read_json(validate_stream, root);

            for (const auto& item : root.get_child("entries")) {
                std::string site =
                    item.second.get<std::string>("site");

                std::string login =
                    item.second.get<std::string>("login");

                std::string password =
                    item.second.get<std::string>("password");

                if (site.empty()) {
                    throw std::runtime_error(
                        "invalid json structure: empty site field"
                    );
                }

                if (login.empty()) {
                    throw std::runtime_error(
                        "invalid json structure: empty login field"
                    );
                }

                if (password.empty()) {
                    throw std::runtime_error(
                        "invalid json structure: empty password field"
                    );
                }
            }
        }
        catch (const boost::property_tree::json_parser_error& e) {
            throw std::runtime_error(
                std::string("invalid input json: ") + e.message()
            );
        }

        std::string pass1 = read_secret_twice(
            "New master password: ",
            "Repeat new master password: "
        );
        SecureStringGuard pass_guard(pass1);

        auto salt = make_salt();
        auto key = derive_key(pass1, salt);
        SecureBufferGuard key_guard(key);

        std::vector<unsigned char> nonce;
        std::vector<unsigned char> tag;

        auto cipher = encrypt_data(
            json_data,
            key,
            nonce,
            tag
        );

        write_vault(salt, nonce, tag, cipher);
        clear_key_cache();

        return 0;
    }

    // Далее предполагается что vault.enc есть!
    Vault vault;
    std::string pwd;
    SecureStringGuard pwd_guard(pwd);

    const bool clipboard_request = vm.count("cp") || vm.count("cl");
    const bool mutating_request =
        vm.count("add") || vm.count("update") || vm.count("delete");
    const bool allow_key_cache = clipboard_request && !mutating_request;
    bool vault_loaded = false;

    if (allow_key_cache) {
        std::vector<unsigned char> key;
        SecureBufferGuard key_guard(key);

        if (load_cached_key(key)) {
            try {
                vault.load_with_key(key);
                vault_loaded = true;
            }
            catch (...) {
                clear_key_cache();
                secure_clear(key);
            }
        }
    }

    if (!vault_loaded) {
        pwd = read_password("Master password: ");

        if (allow_key_cache) {
            std::vector<unsigned char> salt;
            std::vector<unsigned char> nonce;
            std::vector<unsigned char> tag;
            std::vector<unsigned char> cipher;

            if (read_vault(salt, nonce, tag, cipher)) {
                auto key = derive_key(pwd, salt);
                SecureBufferGuard key_guard(key);

                vault.load_with_key(key);
                save_cached_key(key);
                vault_loaded = true;
            }
            else {
                vault.load(pwd);
                vault_loaded = true;
            }
        }
        else {
            vault.load(pwd);
            vault_loaded = true;
        }
    }

    if (vm.count("add")) {
        auto v = vm["add"].as<std::vector<std::string>>();

        if (v.size() != 2) {
            throw std::runtime_error("need: site login");
        }

        std::string entry_password = read_secret_twice(
            "Entry password: ",
            "Repeat entry password: "
        );
        SecureStringGuard entry_password_guard(entry_password);

        vault.add({v[0], v[1], entry_password});
        vault.save(pwd);
        clear_key_cache();
    }

    if (vm.count("update")) {
        auto v = vm["update"].as<std::vector<std::string>>();

        if (v.size() != 2) {
            throw std::runtime_error("need: site login");
        }

        std::string entry_password = read_secret_twice(
            "New entry password: ",
            "Repeat new entry password: "
        );
        SecureStringGuard entry_password_guard(entry_password);

        if (!vault.update({v[0], v[1], entry_password})) {
            throw std::runtime_error("entry not found");
        }

        vault.save(pwd);
        clear_key_cache();
    }

    if (vm.count("show")) {
        auto e = vault.find(vm["show"].as<std::string>());
        if (e) std::cout << e->login << "\n" << e->password << std::endl;
    }

    if (vm.count("cp")) {
        auto e = vault.find(vm["cp"].as<std::string>());
        if (e) {
            copy_to_clipboard(e->password);
            std::cout << "password copied to clipboard" << std::endl;
        }
    }

    if (vm.count("cl")) {
        auto e = vault.find(vm["cl"].as<std::string>());
        if (e) {
            copy_to_clipboard(e->login);
            std::cout << "login copied to clipboard" << std::endl;
        }
    }

    if (vm.count("search")) {
        auto result = vault.search(vm["search"].as<std::string>());

        for (const auto& e : result) {
            std::cout << e.site << std::endl;
        }
    }

    if (vm.count("delete")) {
        std::string site = vm["delete"].as<std::string>();

        if (!vault.remove(site)) {
            throw std::runtime_error("entry not found");
        }

        vault.save(pwd);
        clear_key_cache();
    }

    if (vm.count("all")) {
        std::cout << vault.dump_json() << std::endl;
    }

    if (vm.count("decrypt")) {
        std::ofstream out(storage_dir() + "/vault.json");
        out << vault.dump_json();
    }

    return 0;
}
