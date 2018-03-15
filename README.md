# libCrypto
Cryptopro lib for Node.js

## Установка и настройка пакета

Установить КриптоПро CSP: https://cryptopro.ru/downloads

На данный момент используется версия КриптоПро CSP 4.0 R2.

### Ubuntu

1) Создание контейнера и генерация пары закрытого/открытого ключа в хранилище:

/opt/cprocsp/bin/amd64/csptest -keyset -newkeyset -cont '\\.\HDIMAGE\containerName' -provtype 75 -provider "Crypto-Pro GOST R 34.10-2012 KC1 CSP"

2) Создание запроса на получение сертификата:

/opt/cprocsp/bin/amd64/cryptcp -creatrqst -dn "E=requesteremail@mail.ru, C=RU, CN=localhost, SN=company" -nokeygen -both -ku -cont '\\.\HDIMAGE\containerName' containerName.req

3) Отправить запрос:

http://www.cryptopro.ru/certsrv/

4) Получить сертификат

5) Установить сертификат:

/opt/cprocsp/bin/amd64/certmgr -inst -store umy -file containerName.cer -cont '\\.\HDIMAGE\containerName'


npm install

### Windows

npm install --global --production windows-build-tools

npm install

## Компиляция .so/.dll библиотеки

Установить КриптоПро ЭЦП SDK: https://cryptopro.ru/downloads

В данный момент используется версия КриптоПро ЭЦП SDK 2.0 

### Ubuntu

eval \`./setenv.sh --64\`

make -f MakeNodeCryptopro

### Windows

set PATH=%PATH%C:\Program Files (x86)\Crypto Pro\SDK\include

set INCLUDE=%INCLUDE%C:\Program Files (x86)\Crypto Pro\SDK\include

set LIBPATH=%LIBPATH%C:\Program Files (x86)\Crypto Pro\SDK\lib\amd64

set LIBPATH=%LIBPATH%C:\Program Files (x86)\Crypto Pro\SDK\lib

cl.exe /D_USRDLL /D_WINDLL nodeCryptopro.c /link /DLL /OUT:nodeCryptopro.dll