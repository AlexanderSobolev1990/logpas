# LOGPAS - консольный менеджер паролей / terminal login-password manager #

***

## Описание программы / Program description ##

Простой консольный менеджер паролей / Simple terminal login-password manager

Предполагается, что у вас ubuntu-подобный дистрибутив и есть директория /home / Suppose you have ubuntu-like distro and has /home dir

Хранение паролей организовано в зашифрованном файле / Passwords are stored in encrypted file

```
home/.logpas/vault.enc
```

Файл с паролями защищен мастер-паролем, создаваемым при создании файла vault.enc / Vault file is secured by master-password, which is created at vault.enc creation time

***

## Пакеты, требуемые для сборки / Build package requirements ##

```
xclip 
libsodium-dev 
libssl-dev
libboost-program-options*
```

Могут быть установлены запуском / Can be install by launching:

```
install_required.sh
```

***

## Аргументы запуска приложения / Command line arguments ##

```
Options:
  -h [ --help ]         Show help
  -a [ --add ] arg      Add new site-login-password.
                        Usage:
                           logpas -a <site> <login> <password>
  -s [ --show ] arg     Show 'login' and 'password' for specified 'site'.
                        Usage:
                           logpas -s <site>
  -c [ --copy ] arg     Copy 'password' for specified 'site' to clipboard.
                        Note: clipboard will be cleared in 60 sec.
                        Usage:
                           logpas -c <site>
  -r [ --search ] arg   Search by 'site' field (partial match)
  --delete arg          DELETE 'site' record.
                        Usage:
                           logpas --delete <site>
  -u [ --update ] arg   Update 'login' and 'password' for existing 'site'.
                        Usage:
                           logpas -u <site> <login> <password>
  -d [ --decrypt ]      Decrypt ~/.logpas/vault.enc and save it to ~/.logpas/vault.json
  -e [ --encrypt ] arg  Encrypt specified JSON file to ~/.logpas/vault.enc with specifiing new master-password.
                        WARNING!!! Old vault.enc will be lost!
  -l [ --all ]          Show all records from ~/.logpas/vault.enc to terminal
  -g [ --gen ] arg      Generate password of specified length.
                        Valid characters:
                           a-z A-Z 0-9 !@#$%^&*()_-+=
                        Usage:
                           logpas -g <length>

```

***