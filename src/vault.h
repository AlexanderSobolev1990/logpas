#pragma once
#include "entry.h"
#include <vector>
#include <string>

class Vault {
public:
    bool load(const std::string& password);
    bool save(const std::string& password);

    void add(const Entry& e);
    bool update(const Entry& e);
    bool remove(const std::string& site);
    Entry* find(const std::string& site);
    std::string dump_json() const;

private:
    std::vector<Entry> entries;
};
