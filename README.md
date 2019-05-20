# nodeCryptopro
Node.js package to use Cryptopro.ru functionality

## Установка и настройка пакета

Установить КриптоПро CSP: https://cryptopro.ru/downloads

На данный момент используется версия КриптоПро CSP 4.0 R2.

### Ubuntu

npm install node-cryptopro

### Windows

npm install --global --production windows-build-tools

npm install node-cryptopro

## Использование

### Ubuntu

1) Создание контейнера и генерация пары закрытого/открытого ключа в хранилище:

/opt/cprocsp/bin/amd64/csptest -keyset -newkeyset -cont '\\.\HDIMAGE\containerName' -provtype 75 -provider "Crypto-Pro GOST R 34.10-2012 KC1 CSP"

Для просмотра списка контейнеров используется команда:

/opt/cprocsp/bin/amd64/csptest -keyset -enum_cont -verifycontext -fqcn

2) Создание запроса на получение сертификата:

/opt/cprocsp/bin/amd64/cryptcp -creatrqst -dn "E=requesteremail@mail.ru, C=RU, CN=localhost, SN=company" -nokeygen -both -ku -cont '\\.\HDIMAGE\containerName' containerName.req

3) Отправить запрос:

http://www.cryptopro.ru/certsrv/

4) Получить сертификат

5) Установить сертификат:

/opt/cprocsp/bin/amd64/certmgr -inst -store umy -file containerName.cer -cont '\\.\HDIMAGE\containerName'

## Компиляция .so/.dll библиотеки

### Ubuntu

1) Установить lsb-cprocsp-devel из дистрибутива КриптоПро CSP или КриптоПро OCSP SDK (https://www.cryptopro.ru/products/pki/ocsp/sdk/downloads), например так:

cd linux-amd64_deb

sudo dpkg -i lsb-cprocsp-devel_4.0.0-4_all.deb

2) Установить переменные окружения:

eval \`./setenv.sh --64\`

3) Скомпилировать:

make -f MakeNodeCryptopro

### Windows

1) Установить КриптоПро OCSP SDK (https://www.cryptopro.ru/products/pki/ocsp/sdk/downloads).

2) Установить переменные окружения:

set PATH=%PATH%C:\Program Files (x86)\Crypto Pro\SDK\include

set INCLUDE=%INCLUDE%C:\Program Files (x86)\Crypto Pro\SDK\include

set LIBPATH=%LIBPATH%C:\Program Files (x86)\Crypto Pro\SDK\lib\amd64

set LIBPATH=%LIBPATH%C:\Program Files (x86)\Crypto Pro\SDK\lib

3) Скомпилировать:

cl.exe /D_USRDLL /D_WINDLL nodeCryptopro.c /link /DLL /OUT:nodeCryptopro.dll