#include "vault.h"
#include "crypto.h"
#include "fs.h"
#include <sstream>
#include <regex>
#include <sodium.h>

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
    std::ostringstream ss;
    ss << "[\n";
    for (size_t i = 0; i < entries.size(); ++i) {
        ss << "  {\"site\":\"" << entries[i].site
           << "\",\"login\":\"" << entries[i].login
           << "\",\"password\":\"" << entries[i].password << "\"}";
        if (i + 1 < entries.size()) ss << ",";
        ss << "\n";
    }
    ss << "]";
    return ss.str();
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

    std::regex re(
        R"json(\{"site":"([^"]+)","login":"([^"]+)","password":"([^"]+)"\})json"
    );
    auto begin = std::sregex_iterator(json.begin(), json.end(), re);
    auto end = std::sregex_iterator();

    for (auto i = begin; i != end; ++i) {
        entries.push_back({(*i)[1], (*i)[2], (*i)[3]});
    }

    if (!json.empty()) sodium_memzero(&json[0], json.size());
    return true;
}
