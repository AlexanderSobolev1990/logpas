# LOGPAS - terminal login-password manager / консольный менеджер паролей #

***

## Program description / Описание программы ##

Terminal login-password manager / Консольный менеджер паролей

Suppose you have ubuntu-like distro and has /home dir / Предполагается, что у вас ubuntu-подобный дистрибутив и есть директория /home

Passwords are stored in / Хранение паролей организовано в 

```
home/.logpas/vault.enc
```

Vault file is secured by master-password, which is created at vault.enc creation time / Файл с паролями защищен мастер-паролем, создаваемым при создании файла vault.enc

***

## Build package requirements / Пакеты, требуемые для сборки ##

```
xclip 
libsodium-dev 
libssl-dev
libboost-program-options*
```

Can be install by / Могут быть установлены запуском:

```
install_required.sh
```

***

## Command line arguments / Аргументы запуска приложения ##

```
  -h [ --help ]         Показать справку по всем аргументам
  -a [ --add ] arg      Добавить запись.
                        Использование:
                          logpas -a <site> <login> <password>
                        Пример:
                          logpas -a github.com mylogin mypassword
  -s [ --show ] arg     Показать login и password для указанного site.
                        Использование:
                          logpas -s <site>
  -c [ --copy ] arg     Скопировать password для указанного site в буфер обмена.
                        Буфер будет очищен через 60 секунд, если содержимое не изменилось.
                        Использование:
                          logpas -c <site>
  --search arg          Поиск по site (частичное совпадение)
  -d [ --delete ] arg   Удалить запись по site.
                        Использование:
                          logpas -d <site>
  -u [ --update ] arg   Обновить login/password для существующего site.
                        Использование:
                          logpas -u <site> <login> <password>
  --decrypt             Расшифровать vault и сохранить JSON-файл в ~/.logpas/vault.json
  --encrypt arg         Зашифровать указанный JSON-файл в vault с указанием НОВОГО master-пароля
  --all                 Показать все записи в JSON-формате
  -g [ --gen ] arg      Сгенерировать пароль указанной длины.
                        Допустимые символы:
                          a-z A-Z 0-9 !@#$%^&*()_-+=
                        Использование:
                          logpas -g <length>
```

***