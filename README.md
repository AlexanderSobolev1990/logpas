# LOGPAS - консольный менеджер паролей / terminal login-password manager #

***

## Описание программы / Program description ##

Простой консольный менеджер паролей / Simple terminal login-password manager

Предполагается, что у вас Astra Linux 1.6-1.8, Ubuntu 22.04+ или другой Debian/Ubuntu-подобный дистрибутив и есть директория /home / Suppose you have Astra Linux 1.6-1.8, Ubuntu 22.04+ or another Debian/Ubuntu-like distro and has /home dir

Хранение паролей организовано в зашифрованном файле / Passwords are stored in encrypted file

```
~/.logpas/vault.enc
```

Файл с паролями защищен мастер-паролем, создаваемым при создании файла vault.enc / Vault file is secured by master-password, which is created at vault.enc creation time

***

## Пакеты, требуемые для сборки / Build package requirements ##

```
xclip 
xsel (optional clipboard fallback)
wl-clipboard (optional Wayland clipboard support)
libsodium-dev 
libssl-dev
libboost-program-options-dev
```

Могут быть установлены запуском / Can be installed by launching:

```
install_required.sh
```

***

## Аргументы запуска приложения / Command line arguments ##

```
Options:
  --help        Show help
  --ver         Show version
  --add arg     Add new 'site' and 'login', 'password' will be asked to print.
                Usage:
                   logpas --add <site> <login>
  --show arg    Show 'login' and 'password' for specified 'site'.
                Usage:
                   logpas --show <site>
  --cp arg      Copy 'password' for specified 'site' to clipboard.
                Note: clipboard will be cleared in 60 sec.
                Usage:
                   logpas --cp <site>
  --cl arg      Copy 'login' for specified 'site' to clipboard.
                Note: clipboard will be cleared in 60 sec.
                Usage:
                   logpas --cl <site>
  --srch arg    Search by 'site' field (partial match)
  --del arg     DELETE 'site' record.
                Usage:
                   logpas --del <site>
  --upd arg     Update 'login' and 'password' for existing 'site', 'password' will be asked to print.
                Usage:
                   logpas --upd <site> <login>
  --dec         Decrypt ~/.logpas/vault.enc and save it to ~/.logpas/vault.json
  --enc arg     Encrypt specified JSON file to ~/.logpas/vault.enc with specifying new master-password.
                WARNING!!! Old vault.enc will be lost!
  --all         Show all records from ~/.logpas/vault.enc
  --list        Show all sites from ~/.logpas/vault.enc
  --gen arg     Generate password of specified length.
                Valid characters:
                   a-z A-Z 0-9 !@#$%^&*()_-+=
                Usage:
                   logpas --gen <length>

```

***
