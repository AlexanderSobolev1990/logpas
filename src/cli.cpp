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

int run_cli(int argc, char** argv) {
    namespace po = boost::program_options;

    po::options_description desc("Options", 220);    
    desc.add_options()
    (
        "help,h",
        "Показать справку по всем аргументам"
    )
    (
        "add,a",
        po::value<std::vector<std::string>>()->multitoken(),
        "Добавить запись.\n"
        "Использование:\n"
        "  logpas -a <site> <login> <password>\n"
        "Пример:\n"
        "  logpas -a github.com mylogin mypassword"
    )
    (
        "show,s",
        po::value<std::string>(),
        "Показать login и password для указанного site.\n"
        "Использование:\n"
        "  logpas -s <site>"
    )
    (
        "copy,c",
        po::value<std::string>(),
        "Скопировать password для указанного site в буфер обмена.\n"
        "Буфер будет очищен через 60 секунд, если содержимое не изменилось.\n"
        "Использование:\n"
        "  logpas -c <site>"
    )
    (   "search", 
        po::value<std::string>(), 
        "Поиск по site (частичное совпадение)"
    )
    (
        "delete,d",
        po::value<std::string>(),
        "Удалить запись по site.\n"
        "Использование:\n"
        "  logpas -d <site>"
    )
    (
        "update,u",
        po::value<std::vector<std::string>>()->multitoken(),
        "Обновить login/password для существующего site.\n"
        "Использование:\n"
        "  logpas -u <site> <login> <password>"
    )
    (
        "decrypt",
        "Расшифровать vault и сохранить JSON-файл в ~/.logpas/vault.json"
    )
    (   "encrypt", 
        po::value<std::string>(), 
        "Зашифровать указанный JSON-файл в vault с указанием НОВОГО master-пароля"
    )
    (
        "all",
        "Показать все записи в JSON-формате"
    )
    (
        "gen,g",
        po::value<int>(),
        "Сгенерировать пароль указанной длины.\n"
        "Допустимые символы:\n"
        "  a-z A-Z 0-9 !@#$%^&*()_-+=\n"
        "Использование:\n"
        "  logpas -g <length>"
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

    if (vm.count("encrypt")) {
        std::ifstream in(vm["encrypt"].as<std::string>());

        if (!in) {
            throw std::runtime_error("cannot open input file");
        }

        std::stringstream buffer;
        buffer << in.rdbuf();

        std::string pass1;
        std::string pass2;

        std::cout << "New master password: ";
        pass1 = read_password();

        std::cout << "Repeat master password: ";
        pass2 = read_password();

        if (pass1 != pass2) {
            throw std::runtime_error("password mismatch");
        }

        auto salt = make_salt();
        auto key = derive_key(pass1, salt);

        std::vector<unsigned char> nonce;
        std::vector<unsigned char> tag;

        auto cipher = encrypt_data(buffer.str(), key, nonce, tag);

        write_vault(salt, nonce, tag, cipher);

        sodium_memzero(&pass1[0], pass1.size());
        sodium_memzero(&pass2[0], pass2.size());
        sodium_memzero(key.data(), key.size());
    }

    return 0;
}
