#include "cli.h"
#include "vault.h"
#include "generator.h"
#include "clipboard.h"
#include "secure_input.h"
#include "fs.h"
#include "crypto.h"

#include <boost/program_options.hpp>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <sodium.h>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

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
        "Add new site-login-password.\n"
        "Usage:\n"
        "   logpas -a <site> <login> <password>"
    )
    (
        "show,s",
        po::value<std::string>(),
        "Show 'login' and 'password' for specified 'site'.\n"
        "Usage:\n"
        "   logpas -s <site>"
    )
    (
        "copy,c",
        po::value<std::string>(),
        "Copy 'password' for specified 'site' to clipboard.\n"
        "Note: clipboard will be cleared in 60 sec.\n"
        "Usage:\n"
        "   logpas -c <site>"
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
        "Update 'login' and 'password' for existing 'site'.\n"
        "Usage:\n"
        "   logpas -u <site> <login> <password>"
    )
    (
        "decrypt,d",
        "Decrypt ~/.logpas/vault.enc and save it to ~/.logpas/vault.json"
    )
    (   "encrypt,e", 
        po::value<std::string>(), 
        "Encrypt specified JSON file to ~/.logpas/vault.enc with specifiing new master-password.\n"
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


    if (vm.count("encrypt")) {
        std::ifstream in(vm["encrypt"].as<std::string>());

        if (!in) {
            throw std::runtime_error("cannot open input file");
        }

        std::stringstream buffer;
        buffer << in.rdbuf();

        std::string json_data = buffer.str();

        // validate json before encryption
        try {
            std::stringstream validate_stream(json_data);
            boost::property_tree::ptree root;

            boost::property_tree::read_json(validate_stream, root);

            for (const auto& item : root.get_child("entries")) {
                if (!item.second.count("site") ||
                    !item.second.count("login") ||
                    !item.second.count("password")) {
                    throw std::runtime_error(
                        "invalid json structure: missing fields"
                    );
                }
            }
        }
        catch (const boost::property_tree::json_parser_error& e) {
            throw std::runtime_error(
                std::string("invalid input json: ") + e.message()
            );
        }

        std::string pass1;
        std::string pass2;

        std::cout << "New master password: ";
        pass1 = read_password();

        std::cout << "Repeat new master password: ";
        pass2 = read_password();

        if (pass1 != pass2) {
            throw std::runtime_error("password mismatch");
        }

        auto salt = make_salt();
        auto key = derive_key(pass1, salt);

        std::vector<unsigned char> nonce;
        std::vector<unsigned char> tag;

        auto cipher = encrypt_data(json_data, key, nonce, tag);

        write_vault(salt, nonce, tag, cipher);

        if (!pass1.empty()) sodium_memzero(&pass1[0], pass1.size());
        if (!pass2.empty()) sodium_memzero(&pass2[0], pass2.size());
        sodium_memzero(key.data(), key.size());
        return 0;
    }

    // Далее предполагается что vault.enc есть!
    Vault vault;
    std::cout << "Master password: ";
    std::string pwd = read_password();
    vault.load(pwd);

    if (vm.count("add")) {
        auto v = vm["add"].as<std::vector<std::string>>();
        if (v.size() != 3) throw std::runtime_error("need: site login password");
        vault.add({v[0], v[1], v[2]});
        vault.save(pwd);
    }

    if (vm.count("update")) {
        auto v = vm["update"].as<std::vector<std::string>>();
        if (v.size() != 3) throw std::runtime_error("need: site login password");
        if (!vault.update({v[0], v[1], v[2]}))
            throw std::runtime_error("entry not found");
        vault.save(pwd);
    }

    if (vm.count("show")) {
        auto e = vault.find(vm["show"].as<std::string>());
        if (e) std::cout << e->login << "\n" << e->password << std::endl;
    }

    if (vm.count("copy")) {
        auto e = vault.find(vm["copy"].as<std::string>());
        if (e) copy_to_clipboard(e->password);
    }

    if (vm.count("search")) {
        auto result = vault.search(vm["search"].as<std::string>());

        for (const auto& e : result) {
            std::cout << e.site << std::endl;
        }
    }

    if (vm.count("delete")) {
        std::string site = vm["delete"].as<std::string>();
        vault.remove(site);
        vault.save(pwd);
    }

    if (vm.count("all")) {
        std::cout << vault.dump_json() << std::endl;
    }

    if (vm.count("decrypt")) {
        std::ofstream out(std::string(getenv("HOME")) + "/.logpas/vault.json");
        out << vault.dump_json();
    }

    return 0;
}
