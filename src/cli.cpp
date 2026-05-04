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
#include <sodium.h>
#include <stdexcept>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

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

        return 0;
    }

    // Далее предполагается что vault.enc есть!
    Vault vault;
    std::string pwd = read_password("Master password: ");
    SecureStringGuard pwd_guard(pwd);
    vault.load(pwd);

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
    }

    if (vm.count("show")) {
        auto e = vault.find(vm["show"].as<std::string>());
        if (e) std::cout << e->login << "\n" << e->password << std::endl;
    }

    if (vm.count("cp")) {
        auto e = vault.find(vm["cp"].as<std::string>());
        if (e) copy_to_clipboard(e->password);
    }

    if (vm.count("cl")) {
        auto e = vault.find(vm["cl"].as<std::string>());
        if (e) copy_to_clipboard(e->login);
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
