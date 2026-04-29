#include "vault.h"
#include "crypto.h"
#include "fs.h"
#include <sstream>
#include <sodium.h>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <sys/stat.h>
#include <unistd.h>

static bool file_exists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

void Vault::add(const Entry& e) {
    for (auto& x : entries)
        if (x.site == e.site) throw std::runtime_error("duplicate site");
    entries.push_back(e);
}

bool Vault::update(const Entry& e) {
    for (auto& x : entries)
        if (x.site == e.site) { x = e; return true; }
    return false;
}

bool Vault::remove(const std::string& site) {
    for (auto it = entries.begin(); it != entries.end(); ++it)
        if (it->site == site) { entries.erase(it); return true; }
    return false;
}

Entry* Vault::find(const std::string& site) {
    for (auto& e : entries)
        if (e.site == site) return &e;
    return nullptr;
}

std::vector<Entry> Vault::search(const std::string& q) const {
    std::vector<Entry> result;

    for (const auto& e : entries) {
        if (e.site.find(q) != std::string::npos) {
            result.push_back(e);
        }
    }

    return result;
}

std::string Vault::dump_json() const {
    boost::property_tree::ptree root;
    boost::property_tree::ptree array;

    try {
        for (const auto& e : entries) {
            if (e.site.empty()) {
                throw std::runtime_error("empty site field");
            }
            if (e.login.empty()) {
                throw std::runtime_error("empty login field");
            }
            if (e.password.empty()) {
                throw std::runtime_error("empty password field");
            }

            boost::property_tree::ptree item;

            item.put("site", e.site);
            item.put("login", e.login);
            item.put("password", e.password);

            array.push_back(std::make_pair("", item));
        }

        root.add_child("entries", array);

        std::ostringstream ss;

        boost::property_tree::write_json(ss, root, true); // НЕ компактный формат!

        if (!ss.good()) {
            throw std::runtime_error("json serialization failed");
        }

        return ss.str();
    }
    catch (const std::exception& e) {
        throw std::runtime_error(
            std::string("vault json build failed: ") + e.what()
        );
    }
}

bool Vault::save(const std::string& password) {
    auto salt = make_salt();
    auto key = derive_key(password, salt);
    std::vector<unsigned char> nonce, tag;
    std::string plain = dump_json();
    auto cipher = encrypt_data(plain, key, nonce, tag);

    sodium_memzero(&plain[0], plain.size());
    sodium_memzero(key.data(), key.size());

    return write_vault(salt, nonce, tag, cipher);
}

bool Vault::load(const std::string& password) {
    std::vector<unsigned char> salt, nonce, tag, cipher;
    if (!read_vault(salt, nonce, tag, cipher)) return true;

    auto key = derive_key(password, salt);
    std::string json = decrypt_data(cipher, key, nonce, tag);
    sodium_memzero(key.data(), key.size());

    entries.clear();

    std::stringstream ss(json);

    boost::property_tree::ptree root;

    try {
        std::stringstream ss(json);

        boost::property_tree::ptree root;
        boost::property_tree::read_json(ss, root);

        entries.clear();

        for (const auto& item : root.get_child("entries")) {
            Entry e;

            e.site = item.second.get<std::string>("site");
            e.login = item.second.get<std::string>("login");
            e.password = item.second.get<std::string>("password");

            if (e.site.empty()) {
                throw std::runtime_error("empty site field");
            }
            if (e.login.empty()) {
                throw std::runtime_error("empty login field");
            }
            if (e.password.empty()) {
                throw std::runtime_error("empty password field");
            }

            entries.push_back(e);
        }
    }
    catch (const std::exception& e) {
        throw std::runtime_error(
            std::string("vault parse failed: ") + e.what()
        );
    }

    if (!json.empty()) sodium_memzero(&json[0], json.size());
    return true;
}
