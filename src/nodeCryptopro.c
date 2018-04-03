#include <stdio.h>
#include <string.h>
 
#if defined(WIN32) || defined(_WIN32)
#   include <windows.h>
#   include <wincrypt.h>
#   pragma comment( lib, "Advapi32.lib" )
#   pragma comment(lib,"crypt32.lib")
#   define EXPORT __declspec(dllexport)
#else
#   include <stdlib.h>
#   include <CSP_WinDef.h>
#   include <CSP_WinCrypt.h>
#   define EXPORT
#endif

#include <WinCryptEx.h>

#include "nodeCryptopro.h"

EXPORT CallResult SignHash(
    const char* keyContainer, 
    BYTE* messageBytesArray, 
    DWORD messageBytesArrayLength, 
    BYTE* signatureBytesArray, 
    DWORD* signatureBytesArrayLength
) {
    HCRYPTPROV hProv = 0; // Дескриптор CSP
    HCRYPTHASH hHash = 0;

    BYTE *pbSignature = NULL;
    DWORD signatureLength = 0;

    // Получение дескриптора контекста криптографического провайдера
    if(!CryptAcquireContext( &hProv, keyContainer, NULL, PROV_GOST_2012_256, /*PROV_GOST_2001_DH,*/ 0))
        return HandleError("Error during CryptAcquireContext");

    // Создание объекта функции хеширования
    if(!CryptCreateHash(hProv, CALG_GR3411_2012_256, /*CALG_GR3411,*/0, 0, &hHash))
        return HandleError("Error during CryptCreateHash");

    // Вычисление криптографического хеша буфера
    if(!CryptHashData(hHash, messageBytesArray, messageBytesArrayLength, 0))
        return HandleError("Error during CryptHashData");

    // Определение размера подписи и распределение памяти
    if(!CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, NULL, &signatureLength))
        return HandleError("Error during CryptSignHash");

    // Распределение памяти под буфер подписи
    pbSignature = (BYTE *)malloc(signatureLength);
    if(!pbSignature)
        return HandleError("Out of memory");

    // Подпись объекта функции хеширования
    if(!CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, pbSignature, &signatureLength))
        return HandleError("Error during CryptSignHash");
    
    memcpy(signatureBytesArray, pbSignature, signatureLength);
    memcpy(signatureBytesArrayLength, &signatureLength, sizeof(signatureLength));

    free(pbSignature);
    // Уничтожение объекта функции хеширования
    if(hHash) 
        CryptDestroyHash(hHash);
    if(hProv) 
        CryptReleaseContext(hProv, 0);

    return ResultSuccess();
}

EXPORT CallResult VerifySignature(
    BYTE* messageBytesArray, DWORD messageBytesArrayLength, 
    BYTE* signatureByteArray, DWORD signatureBytesArrayLength,
    BYTE* publicKeyBlob, int publicKeyBlobLength,
    BOOL *verificationResultToReturn
) {
    HCRYPTPROV hProv = 0; // Дескриптор CSP
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hPubKey = 0;

    BOOL verificationResult = FALSE;

    if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_GOST_2012_256, /*PROV_GOST_2001_DH,*/CRYPT_VERIFYCONTEXT))
        return HandleError("CryptAcquireContext failed");

    // Получение откытого ключа отправителя и импортирование его в CSP. Дескриптор открытого ключа возвращается в hPubKey
    if(!CryptImportKey(hProv, publicKeyBlob, publicKeyBlobLength, 0, 0, &hPubKey))
        return HandleError("Public key import failed");

    // Создание объекта функции хеширования
    if(!CryptCreateHash(hProv, CALG_GR3411_2012_256, /*CALG_GR3411, */0, 0, &hHash))
        return HandleError("Error during CryptCreateHash");

    // Вычисление криптографического хеша буфера
    if(!CryptHashData(hHash, messageBytesArray, messageBytesArrayLength, 0))
        return HandleError("Error during CryptHashData");

    // Проверка цифровой подписи
    if(CryptVerifySignature(hHash, signatureByteArray, signatureBytesArrayLength, hPubKey, NULL, 0))
        verificationResult = TRUE;
    else
        verificationResult = FALSE;

    memcpy(verificationResultToReturn, &verificationResult, sizeof(verificationResult));

    if(hHash) 
        CryptDestroyHash(hHash);
    if(hProv) 
        CryptReleaseContext(hProv, 0);

    return ResultSuccess();
}

EXPORT CallResult SignPreparedHash(
    const char* keyContainer, 
    BYTE* hashBytesArray, 
    DWORD hashBytesArrayLength, 
    BYTE* signatureBytesArray, 
    DWORD* signatureBytesArrayLength
) {
    HCRYPTPROV hProv = 0; // Дескриптор CSP
    HCRYPTHASH hHash = 0;

    BYTE *pbSignature = NULL;
    DWORD signatureLength = 0;

    // Получение дескриптора контекста криптографического провайдера
    if(!CryptAcquireContext( &hProv, keyContainer, NULL, PROV_GOST_2012_256, /*PROV_GOST_2001_DH,*/ 0))
        return HandleError("Error during CryptAcquireContext");

    // Создание объекта функции хеширования
    if(!CryptCreateHash(hProv, CALG_GR3411_2012_256, /*CALG_GR3411,*/0, 0, &hHash))
        return HandleError("Error during CryptCreateHash");

   if(!CryptSetHashParam(hHash, HP_HASHVAL, hashBytesArray, 0))
        return HandleError("Error during CryptSetHashParam");

    // Определение размера подписи и распределение памяти
    if(!CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, NULL, &signatureLength))
        return HandleError("Error during CryptSignHash");

    // Распределение памяти под буфер подписи
    pbSignature = (BYTE *)malloc(signatureLength);
    if(!pbSignature)
        return HandleError("Out of memory");

    // Подпись объекта функции хеширования
    if(!CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, pbSignature, &signatureLength))
        return HandleError("Error during CryptSignHash");
    
    memcpy(signatureBytesArray, pbSignature, signatureLength);
    memcpy(signatureBytesArrayLength, &signatureLength, sizeof(signatureLength));

    free(pbSignature);
    // Уничтожение объекта функции хеширования
    if(hHash) 
        CryptDestroyHash(hHash);
    if(hProv) 
        CryptReleaseContext(hProv, 0);

    return ResultSuccess();
}

EXPORT CallResult VerifyPreparedHashSignature(
    BYTE* hashBytesArray, DWORD hashBytesArrayLength, 
    BYTE* signatureByteArray, DWORD signatureBytesArrayLength,
    BYTE* publicKeyBlob, int publicKeyBlobLength,
    BOOL *verificationResultToReturn
) {
    HCRYPTPROV hProv = 0; // Дескриптор CSP
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hPubKey = 0;

    BOOL verificationResult = FALSE;

    if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_GOST_2012_256, /*PROV_GOST_2001_DH,*/CRYPT_VERIFYCONTEXT))
        return HandleError("CryptAcquireContext failed");

    // Получение откытого ключа отправителя и импортирование его в CSP. Дескриптор открытого ключа возвращается в hPubKey
    if(!CryptImportKey(hProv, publicKeyBlob, publicKeyBlobLength, 0, 0, &hPubKey))
        return HandleError("Public key import failed");

    // Создание объекта функции хеширования
    if(!CryptCreateHash(hProv, CALG_GR3411_2012_256, /*CALG_GR3411, */0, 0, &hHash))
        return HandleError("Error during CryptCreateHash");

   if(!CryptSetHashParam(hHash, HP_HASHVAL, hashBytesArray, 0))
        return HandleError("Error during CryptSetHashParam");

    // Проверка цифровой подписи
    if(CryptVerifySignature(hHash, signatureByteArray, signatureBytesArrayLength, hPubKey, NULL, 0))
        verificationResult = TRUE;
    else
        verificationResult = FALSE;

    memcpy(verificationResultToReturn, &verificationResult, sizeof(verificationResult));

    if(hHash) 
        CryptDestroyHash(hHash);
    if(hProv) 
        CryptReleaseContext(hProv, 0);

    return ResultSuccess();
}

EXPORT CallResult Encrypt(
    DWORD* sessionKeyBlobLength, BYTE* sessionKeyBlob, 
    const char* senderContainerName, 
    BYTE* responderPublicKeyBlob, int responderPublicKeyBlobLength,
    BYTE* textToEncrypt, 
    int textToEncryptLength, 
    BYTE* IV, 
    DWORD* IVLength
) {
    HCRYPTPROV hProv = 0; // Дескриптор CSP
    HCRYPTKEY hKey = 0;     // Дескриптор закрытого ключа
    HCRYPTKEY hSessionKey = 0;  // Дескриптор сессионного ключа
    HCRYPTKEY hAgreeKey = 0;        // Дескриптор ключа согласования

    BYTE *pbKeyBlobSimple = NULL;   // Указатель на сессионный ключевой BLOB
    DWORD dwBlobLenSimple;

    BYTE *pbIV = NULL;      // Вектор инициализации сессионного ключа
    DWORD dwIV = 0;

    DWORD bufLen = 0;
    ALG_ID ke_alg = CALG_PRO_EXPORT;

    // Получение дескриптора контейнера получателя с именем senderContainerName, находящегося в рамках провайдера
    if(!CryptAcquireContext(&hProv, senderContainerName, NULL, PROV_GOST_2012_256/*PROV_GOST_2001_DH*/, 0))
       return HandleError("Error during CryptAcquireContext");

    // Получение дескриптора закрытого ключа отправителя
    if(!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey))
        return HandleError("Error during CryptGetUserKey private key");

    // Получение ключа согласования импортом открытого ключа получателя на закрытом ключе отправителя
    if(!CryptImportKey(hProv, responderPublicKeyBlob, responderPublicKeyBlobLength, hKey, 0, &hAgreeKey))
       return HandleError("Error during CryptImportKey public key");

    // Установление алгоритма ключа согласования
    if(!CryptSetKeyParam(hAgreeKey, KP_ALGID, (LPBYTE)&ke_alg, 0))
       return HandleError("Error during CryptSetKeyParam agree key");

    // Генерация сессионного ключа
    if(!CryptGenKey(hProv, CALG_G28147, CRYPT_EXPORTABLE, &hSessionKey))
       return HandleError("Error during CryptGenKey");

     //--------------------------------------------------------------------
    // Зашифрование сессионного ключа
    //--------------------------------------------------------------------

    // Определение размера BLOBа сессионного ключа и распределение памяти
    if(!CryptExportKey( hSessionKey, hAgreeKey, SIMPLEBLOB, 0, NULL, &dwBlobLenSimple))
       return HandleError("Error computing BLOB length");

    pbKeyBlobSimple = (BYTE*)malloc(dwBlobLenSimple);

    if(!pbKeyBlobSimple) 
       return HandleError("Out of memory");

    // Зашифрование сессионного ключа на ключе Agree, экспорт в pbKeyBlobSimple
    if(!CryptExportKey(hSessionKey, hAgreeKey, SIMPLEBLOB, 0, pbKeyBlobSimple, &dwBlobLenSimple))
        return HandleError("Error during CryptExportKey");

    // Определение размера вектора инициализации сессионного ключа
    if(!CryptGetKeyParam(hSessionKey, KP_IV, NULL, &dwIV, 0))
       return HandleError("Error computing IV length");

    pbIV = (BYTE*)malloc(dwIV);
    if (!pbIV)
       return HandleError("Out of memory");
    
    // Определение вектора инициализации сессионного ключа
    if(!CryptGetKeyParam(hSessionKey, KP_IV, pbIV, &dwIV, 0))
       return HandleError("Error during CryptGetKeyParam");

    memcpy(IV, pbIV, dwIV);
    memcpy(IVLength, &dwIV, sizeof(dwIV));

    memcpy(sessionKeyBlob, pbKeyBlobSimple, dwBlobLenSimple);
    memcpy(sessionKeyBlobLength, &dwBlobLenSimple, sizeof(dwBlobLenSimple));

    BOOL bFinal = TRUE;
    bufLen = textToEncryptLength;

    if(!CryptEncrypt(hSessionKey, 0, bFinal, 0, textToEncrypt, &textToEncryptLength, bufLen))
        return HandleError("Encryption failed");

    free(pbIV);
    free(pbKeyBlobSimple);
    if(hAgreeKey)
       CryptDestroyKey(hAgreeKey);
    if(hSessionKey)
       CryptDestroyKey(hSessionKey);
    if(hProv) 
        CryptReleaseContext(hProv, 0);

    return ResultSuccess();
}

EXPORT CallResult Decrypt(
    const char* responderContainerName,
    BYTE* senderPublicKeyBlob,
    int senderPublicKeyBlobLength,
    BYTE* encryptedText, int encryptedTextLength,
    BYTE* IV, int IVLength,
    BYTE* keySimpleBlob, int keySimpleBlobLength
) {
    HCRYPTPROV hProv = 0; // Дескриптор CSP
    HCRYPTKEY hKey = 0;     // Дескриптор закрытого ключа
    HCRYPTKEY hSessionKey = 0;  // Дескриптор сессионного ключа
    HCRYPTKEY hAgreeKey = 0;        // Дескриптор ключа согласования

    ALG_ID ke_alg = CALG_PRO_EXPORT;

   // Получение дескриптора контейнера получателя с именем "responderContainerName", находящегося в рамках провайдера
    if(!CryptAcquireContext(&hProv, responderContainerName, NULL, PROV_GOST_2012_256/*PROV_GOST_2001_DH*/, 0)) {
       return HandleError("Error during CryptAcquireContext");
    }

    if(!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey))
        return HandleError("Error during CryptGetUserKey private key");

    if(!CryptImportKey(hProv, senderPublicKeyBlob, senderPublicKeyBlobLength, hKey, 0, &hAgreeKey))
        return HandleError("Error during CryptImportKey public key");

    if(!CryptSetKeyParam(hAgreeKey, KP_ALGID, (LPBYTE)&ke_alg, 0))
        return HandleError("Error during CryptSetKeyParam agree key");

    if(!CryptImportKey(hProv, keySimpleBlob, keySimpleBlobLength, hAgreeKey, 0, &hSessionKey))
        return HandleError("Error during CryptImportKey session key");

    if(!CryptSetKeyParam(hSessionKey, KP_IV, IV, 0))
        return HandleError("Error during CryptSetKeyParam");

    BOOL bFinal = TRUE;

    if(!CryptDecrypt(hSessionKey, 0, bFinal, 0, encryptedText, &encryptedTextLength))
        return HandleError("Decryption failed");


    if(hAgreeKey)
       CryptDestroyKey(hAgreeKey);
    if(hSessionKey)
       CryptDestroyKey(hSessionKey);
    if(hProv) 
        CryptReleaseContext(hProv, 0);

    return ResultSuccess();
}

EXPORT CallResult CreateHash(BYTE* bytesArrayToHash, DWORD bytesArrayToHashLength, BYTE* hash, DWORD* hashLength) {
    HCRYPTPROV hProv = 0; // Дескриптор CSP
    HCRYPTHASH hHash = 0;

    BYTE rgbHash[GR3411LEN];
    DWORD cbHash = GR3411LEN;

    if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_GOST_2012_256, /*PROV_GOST_2001_DH,*/CRYPT_VERIFYCONTEXT)) {
        return HandleError("CryptAcquireContext failed");
    }

    if(!CryptCreateHash(hProv, /*CALG_GR3411*/CALG_GR3411_2012_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return HandleError("CryptCreateHash failed"); 
    }

    if(!CryptHashData(hHash, bytesArrayToHash, bytesArrayToHashLength, 0)) {
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        return HandleError("CryptHashData failed"); 
    }

    if(!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return HandleError("CryptGetHashParam failed"); 
    }

    memcpy(hash, rgbHash, cbHash);
    memcpy(hashLength, &cbHash, sizeof(cbHash));

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return ResultSuccess();
}

CallResult GetPublicKeyFromCertificateFile(BYTE *publicKeyBlob, DWORD *publicKeyBlobLength, const char *certificateFileName) {
    FILE *certf = NULL;       // Файл, в котором хранится сертификат

    if((certf = fopen(certificateFileName, "rb"))) {
        DWORD cbCert = 2000;
        BYTE  pbCert[2000];
        PCCERT_CONTEXT pCertContext = NULL;
        HCRYPTKEY hPublicKey;
        HCRYPTPROV hProv = 0; // Дескриптор CSP

        BYTE  pbKeyBlob[MAX_PUBLICKEYBLOB_SIZE];
        DWORD dwKeyBlobLen = MAX_PUBLICKEYBLOB_SIZE;

        if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_GOST_2012_256, /*PROV_GOST_2001_DH,*/CRYPT_VERIFYCONTEXT))
            return HandleError("CryptAcquireContext failed");

        cbCert = (DWORD)fread(pbCert, 1, cbCert, certf);
        if(!cbCert)
            return HandleError( "Failed to read certificate" );

        pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbCert, cbCert);

        if (!pCertContext)
            return HandleError( "CertCreateCertificateContext" );

        // Импортируем открытый ключ
        if (!CryptImportPublicKeyInfoEx(hProv, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &(pCertContext->pCertInfo->SubjectPublicKeyInfo), 0, 0, NULL, &hPublicKey)) {
            CertFreeCertificateContext(pCertContext);
            return HandleError( "CryptImportPublicKeyInfoEx" );
        }
        
        // Экспортируем его в BLOB
        if (!CryptExportKey(hPublicKey, 0, PUBLICKEYBLOB, 0, pbKeyBlob, &dwKeyBlobLen)) {
            CryptDestroyKey(hPublicKey);
            return HandleError( "CryptExportKey" );
        }

        memcpy(publicKeyBlob, pbKeyBlob, dwKeyBlobLen);
        memcpy(publicKeyBlobLength, &dwKeyBlobLen, sizeof(dwKeyBlobLen));

        CertFreeCertificateContext(pCertContext);
        CryptDestroyKey(hPublicKey);
        CryptReleaseContext(hProv, 0);
        fclose(certf);
    } else {
        return HandleError( "Problem opening certificate file" );
    }

    return ResultSuccess();
}

CallResult GetPublicKeyFromCertificate(BYTE *publicKeyBlob, DWORD *publicKeyBlobLength, const char *certificateSubjectKey) {
    PCCERT_CONTEXT pCertContext = NULL;    // Контекст сертификата
    HCERTSTORE hStoreHandle = 0;     // Дескриптор хранилища сертификатов
    HCRYPTKEY hPublicKey = 0;     // Дескриптор открытого ключа
    HCRYPTPROV hProv = 0;         // Дескриптор CSP
    
    BYTE *pbKeyBlob = NULL;    // Указатель на ключевой BLOB
    DWORD dwKeyBlobLen;       // Длина ключевого BLOBа получателя
    
    DWORD dwKeySpecSender;

    // Открытие системного хранилища сертификатов.
    hStoreHandle = CertOpenSystemStore(0, "MY");
    
    if(!hStoreHandle) {
        return HandleError( "Error getting store handle");
    }

    pCertContext = CertFindCertificateInStore(hStoreHandle, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, certificateSubjectKey, NULL);

    if(!pCertContext) {
        return HandleError("Error finding certificate");
    }

    //--------------------------------------------------------------------
    // Получение дескриптора CSP, включая доступ к связанному с ним ключевому
    // контейнеру для контекста сертификата pCertContext
//    if(!CryptAcquireCertificatePrivateKey(pCertContext, 0, NULL, &hProv, &dwKeySpecSender, NULL)) {
//        return HandleError("Error during CryptAcquireCertificatePrivateKey");
//    }

    if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_GOST_2012_256, /*PROV_GOST_2001_DH,*/CRYPT_VERIFYCONTEXT))
        return HandleError("CryptAcquireContext failed");

    //--------------------------------------------------------------------
    // Получение дескриптора открытого ключа
    if(!CryptImportPublicKeyInfoEx(hProv, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &(pCertContext->pCertInfo->SubjectPublicKeyInfo), 0, 0, NULL, &hPublicKey)) {
        return HandleError("Error during CryptImportPublicKeyInfoEx public key");
    }

    //--------------------------------------------------------------------
    // Определение размера BLOBа открытого ключа и распределение памяти.
    if(!CryptExportKey(hPublicKey, 0, PUBLICKEYBLOB, 0, NULL, &dwKeyBlobLen)) {
        return HandleError("Error computing BLOB length");
    }

    pbKeyBlob = (BYTE*)malloc(dwKeyBlobLen);

    if(!pbKeyBlob) {
        return HandleError("Out of memory");
    }

    //--------------------------------------------------------------------
    // Экспортирование открытого ключа получателя в BLOB открытого ключа.
    if(!CryptExportKey(hPublicKey, 0, PUBLICKEYBLOB, 0, pbKeyBlob, &dwKeyBlobLen)) {
        return HandleError("Error during CryptExportKey");
    }

    memcpy(publicKeyBlob, pbKeyBlob, dwKeyBlobLen);
    memcpy(publicKeyBlobLength, &dwKeyBlobLen, sizeof(dwKeyBlobLen));


    free(pbKeyBlob);
    CertFreeCertificateContext(pCertContext);
    CryptDestroyKey(hPublicKey);
    CryptReleaseContext(hProv, 0);
    CertCloseStore(hStoreHandle, 0);

    return ResultSuccess();
}

CallResult HandleError(const char *errorMessage) {
    DWORD errorCode = GetLastError();
    if(!errorCode) 
        errorCode = 1;

    CallResult result = {
        errorCode, 
        errorCode, 
        errorMessage
    };

    printf("Error number     : 0x%x\n", result.errorCode);
    printf("Error description: %s\n", result.errorMessage);

    return result;
}
