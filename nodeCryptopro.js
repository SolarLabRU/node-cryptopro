'use strict';

const ffi = require('ffi');
const ref = require('ref');

const G28147_KEYLEN = 32;
const SEANCE_VECTOR_LEN = 8;
const EXPORT_IMIT_SIZE = 4;

const GOST3411_HASH_LENGTH = 32;
const MAX_PUBLICKEYBLOB_SIZE = 200;

const MAX_SIGNATURE_LENGTH = 200;

var ArrayType = require('ref-array');
var byte = ref.types.byte;
var ByteArray = ArrayType(byte);

var Struct = require('ref-struct');

var CallResult = Struct({
	'status': 'int',
	'errorCode': 'int',
	'errorMessage': 'string'
});

const cryptoLib = ffi.Library('./nodeCryptopro', {
	'CreateHash': [CallResult, [ref.refType('byte'), 'int', ref.refType('byte'), ref.refType('int')]],
	'Encrypt': [CallResult, [ref.refType('int'), ref.refType('byte'), 'string', 'string', ref.refType('byte'), 'int', ref.refType('byte'), ref.refType('int')]],
	'Decrypt': [CallResult, ['string', 'string', ref.refType('byte'), 'int', ref.refType('byte'), 'int', ref.refType('byte'), 'int']],
	'SignHash': [CallResult, ['string', ref.refType('byte'), 'int', ref.refType('byte'), ref.refType('int')]],
	'VerifySignature': [CallResult, [ref.refType('byte'), 'int', ref.refType('byte'), 'int', 'string', ref.refType('bool')]]
});


module.exports = {
	createHash: (bytesArrayToHash) => {
		let hashLength = ref.alloc('int');
		let hash = new Uint8Array(GOST3411_HASH_LENGTH);

		let result = cryptoLib.CreateHash(bytesArrayToHash, bytesArrayToHash.length, hash, hashLength);

		if(result.status) {
			throw new Error(result.errorMessage);
		} else {
			return hash.subarray(0, hashLength.deref());
		}
	},
    encrypt: (bytesArrayToEncrypt, senderContainerName, responderCertFilename) => {
		let IV = new Uint8Array(SEANCE_VECTOR_LEN);
		let IVLength = ref.alloc('int');

		let sessionKeyBlobLength = ref.alloc('int');
		let sessionKeyBlob = new Uint8Array( MAX_PUBLICKEYBLOB_SIZE );

		let result = cryptoLib.Encrypt(
			sessionKeyBlobLength, 
			sessionKeyBlob, 
			senderContainerName, 
			responderCertFilename, 
			bytesArrayToEncrypt, bytesArrayToEncrypt.length, 
			IV, IVLength
		);
		if(result.status) {
			throw new Error(result.errorMessage);
		} else {
			return {
				encryptedBytesArray: bytesArrayToEncrypt,
				sessionKeyBlob: sessionKeyBlob.subarray(0, sessionKeyBlobLength.deref()),
				IV: IV.subarray(0, IVLength.deref())
			};
		}
    },
    decrypt: (encryptedBytes, responderContainerName, senderCertFilename, IV, keyBlob) => {
		let result = cryptoLib.Decrypt(
			responderContainerName,
			senderCertFilename,
			encryptedBytes, 
			encryptedBytes.length,
			IV, 
			IV.length,
			keyBlob,
			keyBlob.length
		);
		
		if(result.status) {
			throw new Error(result.errorMessage);
		} else {	
			return encryptedBytes;
		}
    },
	signHash: (keyContainerName, messageBytesArray) => {
		let signatureBytesArrayLength = ref.alloc('int');
		let signatureBytesArray = new Uint8Array( MAX_SIGNATURE_LENGTH );

    	let result = cryptoLib.SignHash(
    		keyContainerName, 
    		messageBytesArray, 
    		messageBytesArray.length, 
    		signatureBytesArray, 
    		signatureBytesArrayLength
    	);
		if(result.status) {
			throw new Error(result.errorMessage);
		} else {	
    		return signatureBytesArray.subarray(0, signatureBytesArrayLength.deref());
    	}
    },
    verifySignature: (messageBytesArray, signatureBytesArray, certFilename) => {
    	let verificationResult = ref.alloc('bool');
    	let result = cryptoLib.VerifySignature(messageBytesArray, messageBytesArray.length, signatureBytesArray, signatureBytesArray.length, certFilename, verificationResult);
		
		if(result.status) {
			throw new Error(result.errorMessage);
		} else {	
	    	return verificationResult.deref();
	    }
    }
};
