'use strict';
const Path = require('path');

const pathToNodeCryptopro = Path.resolve(__dirname, '.');

let pathToNodeCryptoproLib = '';

if(process.platform == 'win32') {
	pathToNodeCryptoproLib = pathToNodeCryptopro + '/lib/nodeCryptopro.dll';
} else {
	pathToNodeCryptoproLib = pathToNodeCryptopro + '/lib/nodeCryptopro.so';
}

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

const cryptoLib = ffi.Library(pathToNodeCryptoproLib, {
	'CreateHash': [CallResult, [ref.refType('byte'), 'int', ref.refType('byte'), ref.refType('int')]],
	'Encrypt': [CallResult, [ref.refType('int'), ref.refType('byte'), 'string', 'string', ref.refType('byte'), 'int', ref.refType('byte'), ref.refType('int')]],
	'Decrypt': [CallResult, ['string', 'string', ref.refType('byte'), 'int', ref.refType('byte'), 'int', ref.refType('byte'), 'int']],
	'SignHash': [CallResult, ['string', ref.refType('byte'), 'int', ref.refType('byte'), ref.refType('int')]],
	'VerifySignature': [CallResult, [ref.refType('byte'), 'int', ref.refType('byte'), 'int', 'string', ref.refType('bool')]]
});


module.exports = {
	/**
	 * Вычисление хеша по алгоритму ГОСТ Р 34.11-2012 длинной 256 бит
	 *
	 * @param {Uint8Array} bytesArrayToHash Исходные данные для хеширования
	 *
	 * @return {Uint8Array} Хеш
	 */
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

	/**
	 * Объект, содержащий результаты шифрования 
	 *
	 * @typedef {Object} EncryptionResult
	 * @property {Uint8Array} encryptedBytesArray Зашифрованное сообщение
	 * @property {Uint8Array} sessionKeyBlob Зашифрованный сессионный ключ в формате SIMPLEBLOB
	 * @property {Uint8Array} IV Вектор инициализации сессионного ключа
	 */

	/**
	 * Шифрование по алгоритму ГОСТ 28147
	 * 
	 * Шифрование производится на сессионном ключе.
	 * Для передачи на сторону получателя сессионный ключ шифруется на ключе согласования по алгоритму CALG_PRO_EXPORT и экспортируется в формате SIMPLEBLOB.
	 * Ключ согласования получается импортом открытого ключа получателя на закрытом ключе отправителя.
	 *
	 * Используется провайдер типа PROV_GOST_2012_256 и ключи алгоритма ГОСТ Р 34.10-2012 длины 256 бит (длина открытого ключа 512 бит).
	 *
	 * https://cpdn.cryptopro.ru/content/csp40/html/group___c_s_p_examples_4_0vs3_6.html
	 * https://cpdn.cryptopro.ru/content/csp40/html/group___pro_c_s_p_key_1gd56b0fb8e9d9c0278e45eb1994c38161.html
	 *
	 * @param {Uint8Array} bytesArrayToEncrypt Исходные данные для шифрования
	 * @param {String} senderContainerName Имя контейнера, содержащего закрытый ключ отправителя
	 * @param {String} responderCertFilename Путь к файлу сертификата открытого ключа получателя
	 *
	 * @return {EncryptionResult}  
	 */
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
	/**
	 * Дешифрование по алгоритму ГОСТ 28147
	 *
	 * Сессионный ключ в формате SIMPLEBLOB расшифровывается на ключе согласования по алгоритму CALG_PRO_EXPORT.
	 * Ключ согласования получается импортом открытого ключа отправителя на закрытом ключе получателя.
	 *
	 * @param {Uint8Array} encryptedBytes Массив байтов зашифрованных данных
	 * @param {String} responderContainerName Имя контейнера, содержащего закрытый ключ получателя
	 * @param {String} senderCertFilename Путь к файлу сертификата открытого ключа отправителя
	 * @param {Uint8Array} IV Вектор инициализации сессионного ключа
	 * @param {Uint8Array} keyBlob Зашифрованный сессионный ключ в формате SIMPLEBLOB
	 *
	 * @return {Uint8Array} Массив байтов расшифрованного сообщения
	 */
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
	/**
	 * Вычисление хеша сообщения по ГОСТ 34.11-2012 и генерация цифровой подписи
	 *
	 * @param {String} keyContainerName Имя контейнера, содержащего закрытый ключ
	 * @param {Uint8Array} messageBytesArray Массив байтов исходного сообщения
	 * @return {Uint8Array} Массив байтов цифровой подписи
	 */
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
	/**
	 * Верификация цифровой подписи хеша сообщения
	 *
	 * @param {Uint8Array} messageBytesArray Массив байтов исходного сообщения
	 * @param {Uint8Array} signatureBytesArray Массив байтов исходного сообщения
	 * @param {String} certFilename Путь к файлу сертификата открытого ключа
	 * @return {Boolean} Результат верификации
	 */
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
