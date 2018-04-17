#ifndef nodeCryptopro_h__
#define nodeCryptopro_h__

#if defined(WIN32) || defined(_WIN32)
#    define EXPORT __declspec(dllexport)
#else
#    define EXPORT
#endif

#define GR3411LEN  32//64

#define MAX_PUBLICKEYBLOB_SIZE 200

typedef struct CallResult {
    int status;
    DWORD errorCode;
    char *errorMessage;
} CallResult;

CallResult ResultSuccess() {
    CallResult result = {0, 0, ""};
    return result;
}

CallResult HandleError(const char *s);

EXPORT CallResult GetPublicKeyFromCertificateFile(BYTE *publicKeyBlob, DWORD *publicKeyBlobLength, const char *certificateFileName);

EXPORT CallResult GetPublicKeyFromCertificate(BYTE *publicKeyBlob, DWORD *publicKeyBlobLength, const char *certificateSubjectKey);

EXPORT CallResult GenerateSessionKey(
    DWORD* sessionKeyBlobLength, BYTE* sessionKeyBlob, 
    const char* senderContainerName, 
    BYTE* responderPublicKeyBlob, int responderPublicKeyBlobLength,
    BYTE* IV, DWORD* IVLength
);

EXPORT CallResult SignHash(
    const char* keyContainer, 
    BYTE* messageBytesArray, 
    DWORD messageBytesArrayLength, 
    BYTE* signatureBytesArray, 
    DWORD* signatureBytesArrayLength,
    BYTE* hash
);

EXPORT CallResult VerifySignature(
    BYTE* messageBytesArray, DWORD messageBytesArrayLength, 
    BYTE* signatureByteArray, DWORD signatureBytesArrayLength,
    BYTE* publicKeyBlob, int publicKeyBlobLength,
    BOOL *verificationResultToReturn
);

EXPORT CallResult SignPreparedHash(
    const char* keyContainer, 
    BYTE* hashBytesArray, 
    DWORD hashBytesArrayLength, 
    BYTE* signatureBytesArray, 
    DWORD* signatureBytesArrayLength
);

EXPORT CallResult VerifyPreparedHashSignature(
    BYTE* hashBytesArray, DWORD hashBytesArrayLength, 
    BYTE* signatureByteArray, DWORD signatureBytesArrayLength,
    BYTE* publicKeyBlob, int publicKeyBlobLength,
    BOOL *verificationResultToReturn,
    BYTE* hash
);

EXPORT CallResult Encrypt(
    DWORD* sessionKeyBlobLength, BYTE* sessionKeyBlob, 
    const char* senderContainerName, 
    BYTE* responderPublicKeyBlob,
    int responderPublicKeyBlobLength,
    BYTE* textToEncrypt, 
    int textToEncryptLength, 
    BYTE* IV, 
    DWORD* IVLength
);

EXPORT CallResult EncryptWithSessionKey(
    BYTE* sessionKeySimpleBlob, DWORD sessionKeySimpleBlobLength,
    const char* senderContainerName, 
    BYTE* responderPublicKeyBlob, int responderPublicKeyBlobLength,
    BYTE* textToEncrypt, 
    int textToEncryptLength, 
    BYTE* IV, 
    int IVLength
);

EXPORT CallResult RecodeSessionKey(
    BYTE* sessionKeySimpleBlob, DWORD sessionKeySimpleBlobLength,
    const char* senderContainerName, 
    BYTE* oldResponderPublicKeyBlob, int oldResponderPublicKeyBlobLength,
    BYTE* newResponderPublicKeyBlob, int newResponderPublicKeyBlobLength,
    BYTE* IV, int IVLength
);

EXPORT CallResult Decrypt(
    const char* responderContainerName,
    BYTE* senderPublicKeyBlob,
    int senderPublicKeyBlobLength,
    BYTE* encryptedText, int encryptedTextLength,
    BYTE* IV, int IVLength,
    BYTE* keySimpleBlob, int keySimpleBlobLength
);

EXPORT CallResult CreateHash(BYTE* bytesArrayToHash, DWORD bytesArrayToHashLength, BYTE* hash, DWORD* hashLength);

#endif  // nodeCryptopro_h__
