'use strict';

const expect = require('chai').expect;

const nodeCryptopro = require('../index')("CALG_PRO12_EXPORT", "CRYPT_MODE_CNT");


//Имя контейнера с ключами отправителя
const senderContainerName = "55298654e-d073-f75e-9368-0847d712bb2";// "5973e5bc6-1e43-6206-c603-21fdd08867e";

//Путь к файлу с сертификатом открытого ключа отправителя
const senderCertFilename = "./55298654e-d073-f75e-9368-0847d712bb2.cer";// "2012_Cert.cer";

//Имя контейнера с ключами получателя
const responderContainerName = "5973e5bc6-1e43-6206-c603-21fdd08867e";

//Путь к файлу с сертификатом открытого ключа получателя
const responderCertFilename =  "./2012_Cert.cer";


describe('Тесты', function () {

	const sourceMessage = "text message for tests";
	const buffer = Buffer.from(sourceMessage);
	const sourceMessageBytes = new Uint8Array(buffer);

//	console.log('sourceMessage: ' + buffer.toString('hex'));

	const hashForSourceMessage = new Uint8Array([82,181,47,23,1,228,41,72,41,214,88,194,195,191,190,222,223,73,66,111,196,65,133,235,206,122,89,171,160,130,48,90]);
//	console.log("hashForSourceMessage: " + Buffer.from(hashForSourceMessage).toString('hex'));

	const publicKeyBytes = [144,129,142,86,169,62,26,195,207,130,70,122,105,84,35,108,162,39,114,195,205,130,86,214,24,187,179,50,178,170,134,15,82,165,222,213,0,31,89,235,98,208,30,89,111,242,79,159,234,213,149,143,34,11,145,117,195,31,87,82,221,2,83,139];
//	console.log("publicKeyBytesHex: " + Buffer.from(publicKeyBytes).toString('hex'));

	const certificateSubjectKey = "Tokarev2012_3";// 'NewCert2012';

	let hashSignatureForSourceMessage = "";

	let signatureForPreparedHash = "";

	let publicKeyBlob = {};

	let generatedSessionKey = {};

	let encryptionResult = {};
	let encryptionResult2 = {};

	it('Вычисление хеша', async () => {
		const hash = nodeCryptopro.createHash(sourceMessageBytes);
		
		expect(hash).to.deep.equal(hashForSourceMessage);
	});

	it('Загрузка публичного ключа из контейнера', async () => {
		publicKeyBlob = nodeCryptopro.GetPublicKeyFromCertificate(certificateSubjectKey);

		expect(publicKeyBlob).to.have.lengthOf(101);
	});	

	it('Загрузка публичного ключа из файла сертификата', async () => {
		const certificateFilePath = './55298654e-d073-f75e-9368-0847d712bb2.cer';

		publicKeyBlob = nodeCryptopro.GetPublicKeyFromCertificateFile(certificateFilePath);

		expect(publicKeyBlob).to.have.lengthOf(101);
	});

	it('Получение дескриптора контейнера', async () => {
		const result = nodeCryptopro.acquireContextForContainer(senderContainerName);
		
		expect(result).to.equal(true);
	});

	it('Вычисление цифровой подписи хеша', async () => {
		hashSignatureForSourceMessage = nodeCryptopro.signHash(senderContainerName, sourceMessageBytes);
		
		expect(hashSignatureForSourceMessage).to.have.lengthOf(64);
	});

	it('Проверка цифровой подписи хеша', async () => {
		const isVerified = nodeCryptopro.verifySignature(sourceMessageBytes, hashSignatureForSourceMessage, publicKeyBlob);

		expect(isVerified).to.equal(true);
	});

	it('Вычисление цифровой подписи предварительно подготовленного хеша', async () => {
		signatureForPreparedHash = nodeCryptopro.signPreparedHash(senderContainerName, hashForSourceMessage);
		
//		console.log("signatureForPreparedHash: " + Buffer.from(signatureForPreparedHash).toString('hex'));

		expect(signatureForPreparedHash).to.have.lengthOf(64);
	});

	it('Проверка цифровой подписи предварительно подготовленного хеша', async () => {
		const responderPublicKeyBlob = publicKeyBlob;

		const isVerified = nodeCryptopro.verifyPreparedHashSignature(hashForSourceMessage, signatureForPreparedHash, responderPublicKeyBlob);

//		console.log("responderPublicKeyBlob: " + Buffer.from(responderPublicKeyBlob).toString('hex'));
		
		expect(isVerified).to.equal(true);
	});

	it('Проверка цифровой подписи предварительно подготовленного хеша в GostCrypto', async () => {
		const publicKeyBlobHeader = [6,32,0,0,73,46,0,0,77,65,71,49,0,2,0,0,48,19,6,7,42,133,3,2,2,36,0,6,8,42,133,3,7,1,1,2,2];

		const responderPublicKeyBlob = publicKeyBlob;

		const pkHex = "953a0a996e33601678ac36f052cd8e98963f5088c080bfaeeea49591ed0ab84012cf75816eb883735e1738678e73a6ad85757cc6b17e39381937b2128c473d21";

		const pkHexN = "06200000492e00004d41473100020000301306072a85030202230106082a85030701010202abcda6f379d7b7aa2831c989ac49d33e4aa26d9aca4a78d1c06e925d88407d881e883cb14dac56442e1ba01d1267bc60fd140e6e65ea93b86a8e0c7960efb83f";
		
		const pkBytes = new Uint8Array( Buffer.from(pkHex, 'hex') );
		const pkBytesN = new Uint8Array( Buffer.from(pkHexN, 'hex') );

		const hash = new Uint8Array( Buffer.from("52b52f1701e4294829d658c2c3bfbededf49426fc44185ebce7a59aba082305a", "hex") );
		const sign = new Uint8Array( Buffer.from("a9c3dd99a1a32007509fd083d7020e7888eaedfd6a1159caf5d15fac5048e91d57beb27770d8a2891aa297f6d64bcccfa598194c0bd181360913e5de0c1fd784", "hex") );


		const isVerified = nodeCryptopro.verifyPreparedHashSignature(hash, sign, pkBytesN);

		expect(isVerified).to.equal(true);
	});

	it('Верификация подписи, созданной с помощью SignPreparedHash, функцией VerifySignature', async () => {
		const responderPublicKeyBlob = publicKeyBlob;

		const isVerified = nodeCryptopro.verifySignature(sourceMessageBytes, signatureForPreparedHash, responderPublicKeyBlob);

		expect(isVerified).to.equal(true);
	});

	it('Шифрование сообщения по алгоритму ГОСТ 28147', async () => {
		const responderPublicKeyBlob = nodeCryptopro.GetPublicKeyFromCertificateFile(responderCertFilename);
		const senderPublicKeyBlob = nodeCryptopro.GetPublicKeyFromCertificateFile(senderCertFilename);

		encryptionResult = nodeCryptopro.encrypt(sourceMessageBytes, senderContainerName, responderPublicKeyBlob, "CALG_PRO_EXPORT");

/*console.log("encryptedBytesArray: " + Buffer.from(encryptionResult.encryptedBytesArray).toString('hex'));
console.log("sessionKeyBlob: " + Buffer.from(encryptionResult.sessionKeyBlob).toString('hex'));
console.log("IV: " + Buffer.from(encryptionResult.IV).toString('hex'));
console.log("sender pk: " + Buffer.from(senderPublicKeyBlob).toString('hex'));
console.log("responder pk: " + Buffer.from(responderPublicKeyBlob).toString('hex'));
*/
		expect(encryptionResult.encryptedBytesArray).to.have.lengthOf(sourceMessageBytes.length);
		expect(encryptionResult.sessionKeyBlob).to.have.lengthOf(73);
		expect(encryptionResult.IV).to.have.lengthOf(8);
	});

	it('Дешифрование сообщения по алгоритму ГОСТ 28147', async () => {
		const senderPublicKeyBlob = nodeCryptopro.GetPublicKeyFromCertificateFile(senderCertFilename);

		let decryptedBytes = nodeCryptopro.decrypt(
			encryptionResult.encryptedBytesArray, 
			responderContainerName,
			senderPublicKeyBlob,
			encryptionResult.IV,
			encryptionResult.sessionKeyBlob,
			"CALG_PRO12_EXPORT");

		const decryptedMessage = (new Buffer(decryptedBytes)).toString();

		expect(decryptedMessage).to.equal(sourceMessage);
	});

	it('Шифрование сообщения по алгоритму ГОСТ 28147 на готовом сессионном ключе', async () => {
		const responderPublicKeyBlob = nodeCryptopro.GetPublicKeyFromCertificateFile(responderCertFilename);

		generatedSessionKey = nodeCryptopro.generateSessionKey(senderContainerName, responderPublicKeyBlob);
	
		encryptionResult2 = await nodeCryptopro.encryptWithSessionKey(
			sourceMessageBytes, 
			senderContainerName, 
			responderPublicKeyBlob, 
			generatedSessionKey.sessionKeyBlob, 
			generatedSessionKey.IV
		);

		expect(encryptionResult2.encryptedBytesArray).to.have.lengthOf(sourceMessageBytes.length);
	});

	it('Дешифрование сообщения по алгоритму ГОСТ 28147 на готовом сессионном ключе', async () => {
		const senderPublicKeyBlob = nodeCryptopro.GetPublicKeyFromCertificateFile(senderCertFilename);

		let decryptedBytes = nodeCryptopro.decrypt(
			encryptionResult2.encryptedBytesArray, 
			responderContainerName,
			senderPublicKeyBlob,
			generatedSessionKey.IV,
			generatedSessionKey.sessionKeyBlob);


		const decryptedMessage = (new Buffer(decryptedBytes)).toString();

		expect(decryptedMessage).to.equal(sourceMessage);
	});

	it('Перекодирование сессионного ключа', async () => {
		const oldResponderPublicKeyBlob = nodeCryptopro.GetPublicKeyFromCertificateFile(responderCertFilename);
		const newResponderPublicKeyBlob = nodeCryptopro.GetPublicKeyFromCertificateFile(senderCertFilename);

		let generatedSessionKey2 = nodeCryptopro.generateSessionKey(senderContainerName, oldResponderPublicKeyBlob);

		let result = nodeCryptopro.recodeSessionKey(
			generatedSessionKey2.sessionKeyBlob, 
			generatedSessionKey2.IV, 
			senderContainerName, 
			oldResponderPublicKeyBlob, 
			newResponderPublicKeyBlob);

		let result2 = nodeCryptopro.recodeSessionKey(
			result.sessionKeyBlob, 
			result.IV, 
			senderContainerName, 
			newResponderPublicKeyBlob,
			oldResponderPublicKeyBlob);

		expect(1).to.equal(1);
	});

	it('Перекодирование сессионного ключа со сменой ключевого контейнера', async () => {
		const oldResponderPublicKeyBlob = publicKeyBlob;
		const newResponderPublicKeyBlob = publicKeyBlob;
		const oldSenderContainerName = senderContainerName;
		const newSenderContainerName = senderContainerName;

		let generatedSessionKey2 = nodeCryptopro.generateSessionKey(oldSenderContainerName, oldResponderPublicKeyBlob);

		let result = nodeCryptopro.recodeSessionKeyForNewContainer(
			generatedSessionKey2.sessionKeyBlob, 
			generatedSessionKey2.IV, 
			oldSenderContainerName,
			newSenderContainerName, 
			oldResponderPublicKeyBlob, 
			newResponderPublicKeyBlob);

		expect(1).to.equal(1);
	});


	it('Генерация сессионного ключа', async () => {
		const sessionKey = nodeCryptopro.generateSessionKey(senderContainerName, publicKeyBlob);

		expect(sessionKey.sessionKeyBlob).to.have.lengthOf(73);
		expect(sessionKey.IV).to.have.lengthOf(8);
	});


	it('Шифрование и дешифрование сообщения с перекодированием сессионного ключа', async () => {
		const nodePublicKeyBlob = nodeCryptopro.GetPublicKeyFromCertificateFile(senderCertFilename);
		const nodeContainerName = senderContainerName;

		const clientPublicKeyBlob = nodeCryptopro.GetPublicKeyFromCertificateFile(responderCertFilename);
		const clientContainerName = responderContainerName;

		const generatedSessionKey = nodeCryptopro.generateSessionKey(nodeContainerName, nodePublicKeyBlob);
		
		const encryptionResult = await nodeCryptopro.encryptWithSessionKey(
			sourceMessageBytes, 
			nodeContainerName, 
			nodePublicKeyBlob, 
			generatedSessionKey.sessionKeyBlob, 
			generatedSessionKey.IV
		);

		let recodedSessionKey = nodeCryptopro.recodeSessionKey(
			generatedSessionKey.sessionKeyBlob, 
			generatedSessionKey.IV, 
			nodeContainerName, 
			nodePublicKeyBlob, 
			clientPublicKeyBlob);

		let decryptedBytes = nodeCryptopro.decrypt(
			encryptionResult.encryptedBytesArray, 
			clientContainerName,
			nodePublicKeyBlob,
			recodedSessionKey.IV,
			recodedSessionKey.sessionKeyBlob);


		const decryptedMessage = (new Buffer(decryptedBytes)).toString();


		expect(decryptedMessage).to.equal(sourceMessage);
	});

	it('Дешифрование сообщения от КриптоПро Browser Plugin', async () => {
		const containerName = "5973e5bc6-1e43-6206-c603-21fdd08867e";
		
		const KP_CIPHEROID = "312E322E3634332E372E312E322E352E312E3100";
		const pkBlob = new Uint8Array( Buffer.from("0A200000492E00004D41473100020000301306072A85030202240006082A850307010102022E072B2C9D9F94A907BC7FCAFC50341AFFD294313E26388963F11467D50DE165C042F622A6BB39D766C619F8F366857CB9E3F5C429501BD6AEBE547511332612", 'hex') );
		const sessionKey = new Uint8Array( Buffer.from("012000001E660000FD514A371E6600006F82A6A5D9A3CEC7EEA4EE0F196CB50EDDF61D5062A6A61C10F8025D10530C139F473A08F0EF8CB0157EA30C300906072A850302021F01", 'hex') );
		
		const iv = new Uint8Array( Buffer.from("A397A8F0473F0ABC", 'hex') );
		const encryptedBytesArray = new Uint8Array( Buffer.from("0231E3C1", 'hex') );

		let decryptedBytes = nodeCryptopro.decrypt(
			encryptedBytesArray, 
			containerName,
			pkBlob,
			iv,
			sessionKey,
			"CALG_PRO12_EXPORT");

		const decryptedMessage = Buffer.from(decryptedBytes).toString();
		console.log("decryptedMessage: " + decryptedMessage);

		expect(decryptedMessage).to.equal(sourceMessage);
	});
/*
	it('Дешифрование сообщения от микросервиса dbg.crypto', async () => {
		const containerName = "5973e5bc6-1e43-6206-c603-21fdd08867e";
		
		const senderPublicKeyBlob = new Uint8Array( Buffer.from("06200000492e00004d41473100020000301306072a85030202240006082a85030701010202e21e0ca695409ee93470eb4d3386815b1ac451e105cf778feadc53836ab2749650994b6715ebf381bd64a6763d9ccaac8821241f4cb8e17350d56d4eebd5504d", 'hex') );
		//nodeCryptopro.GetPublicKeyFromCertificateFile("./55298654e-d073-f75e-9368-0847d712bb2.cer");
//		
		const pkBlob = new Uint8Array( Buffer.from("", 'hex') );
		const sessionKey = new Uint8Array( Buffer.from("012000001e660000fd514a371e6600004d9b1b1b6b81b9a7705a97293a4c9c99cb3ace94969fce72760668595674e7429f37f9812a860230b8db2981300b06092a8503070102050101", 'hex') );
		
		const iv = new Uint8Array( Buffer.from("b7b37aa3b9606075", 'hex') );
		const encryptedBytesArray = new Uint8Array( Buffer.from("2583ab35", 'hex') );

		let decryptedBytes = nodeCryptopro.decrypt(
			encryptedBytesArray, 
			containerName,
			senderPublicKeyBlob,
			iv,
			sessionKey);

		const decryptedMessage = (new Buffer(decryptedBytes)).toString();
		console.log("decryptedMessage: " + decryptedMessage);

		expect(decryptedMessage).to.equal("test");
	});
*/

/*	it('Дешифрование сообщения с Платформы', async () => {
		const containerName = "5973e5bc6-1e43-6206-c603-21fdd08867e";
		const pkBlob = new Uint8Array([6,32,0,0,73,46,0,0,77,65,71,49,0,2,0,0,48,19,6,7,42,133,3,2,2,36,0,6,8,42,133,3,7,1,1,2,2,144,129,142,86,169,62,26,195,207,130,70,122,105,84,35,108,162,39,114,195,205,130,86,214,24,187,179,50,178,170,134,15,82,165,222,213,0,31,89,235,98,208,30,89,111,242,79,159,234,213,149,143,34,11,145,117,195,31,87,82,221,2,83,139]);
		const sessionKeyBytes = new Uint8Array([1,32,0,0,30,102,0,0,253,81,74,55,30,102,0,0,108,55,242,240,222,51,1,65,194,217,203,30,166,86,252,69,35,116,246,28,78,216,183,39,55,162,77,155,63,221,97,46,163,170,229,17,18,46,247,221,253,137,227,118,48,11,6,9,42,133,3,7,1,2,5,1,1]);
		const iv = new Uint8Array([49,188,197,134,61,238,168,89]);
		const encryptedBytesArray = new Uint8Array([108,131,157,179,80,86,80,196,96,225,216]);

		const senderPublicKeyBlob = nodeCryptopro.GetPublicKeyFromCertificateFile("./2012_Cert.cer");//("./55298654e-d073-f75e-9368-0847d712bb2.cer");
		console.log("senderPublicKeyBlob (2012_Cert.cer): " + senderPublicKeyBlob);

		const senderPublicKeyBlob2 = nodeCryptopro.GetPublicKeyFromCertificateFile("./55298654e-d073-f75e-9368-0847d712bb2.cer");
		console.log("senderPublicKeyBlob (55298654e-d073-f75e-9368-0847d712bb2): " + senderPublicKeyBlob2);

		const publicKeyBlobFromContainer = nodeCryptopro.GetPublicKeyFromCertificate("vstroganov@mail.ru");
		console.log("publicKeyBlobFromContainer ('Tokarev2012_3'): " + publicKeyBlobFromContainer);

		let decryptedBytes = nodeCryptopro.decrypt(
			encryptedBytesArray, 
			containerName,
			senderPublicKeyBlob2,
			iv,
			sessionKeyBytes);

		const decryptedMessage = (new Buffer(decryptedBytes)).toString();
console.log("decryptedMessage: " + decryptedMessage);

		expect(decryptedMessage).to.equal(sourceMessage);
	});*/

});

