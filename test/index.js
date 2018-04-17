'use strict';

const expect = require('chai').expect;

const nodeCryptopro = require('../index');

//Имя контейнера с ключами отправителя
const senderContainerName = "5973e5bc6-1e43-6206-c603-21fdd08867e";

//Путь к файлу с сертификатом открытого ключа отправителя
const senderCertFilename = "2012_Cert.cer";

//Имя контейнера с ключами получателя
const responderContainerName = "5973e5bc6-1e43-6206-c603-21fdd08867e";

//Путь к файлу с сертификатом открытого ключа получателя
const responderCertFilename =  "2012_Cert.cer";


describe('Тесты', function () {

	const sourceMessage = "text message for tests";
	const buffer = Buffer.from(sourceMessage);
	const sourceMessageBytes = new Uint8Array(buffer);

	console.log('sourceMessage: ' + buffer.toString('hex'));

	const hashForSourceMessage = new Uint8Array([82,181,47,23,1,228,41,72,41,214,88,194,195,191,190,222,223,73,66,111,196,65,133,235,206,122,89,171,160,130,48,90]);


	const certificateSubjectKey = 'NewCert2012';

	let hashSignatureForSourceMessage = "";

	let signatureForPreparedHash = "";

	let publicKeyBlob = {};

	let generatedSessionKey = {};

	let encryptionResult = {};
	let encryptionResult2 = {};

	it('Вычисление хеша', async () => {
		const hash = nodeCryptopro.createHash(sourceMessageBytes);
		console.log('hash from CreateHash: ' + Buffer.from(hash).toString('hex'));
		
		expect(hash).to.deep.equal(hashForSourceMessage);
	});

	it('Загрузка публичного ключа из контейнера', async () => {
		publicKeyBlob = nodeCryptopro.GetPublicKeyFromCertificate(certificateSubjectKey);

		expect(publicKeyBlob).to.have.lengthOf(101);
	});	

	it('Загрузка публичного ключа из файла сертификата', async () => {
		const certificateFilePath = './2012_Cert.cer';

		publicKeyBlob = nodeCryptopro.GetPublicKeyFromCertificateFile(certificateFilePath);

		expect(publicKeyBlob).to.have.lengthOf(101);
	});	

	it('Вычисление цифровой подписи хеша', async () => {
		hashSignatureForSourceMessage = nodeCryptopro.signHash(senderContainerName, sourceMessageBytes);
		console.log('sign from signHash: ' + Buffer.from(hashSignatureForSourceMessage).toString('hex'));
		
		expect(hashSignatureForSourceMessage).to.have.lengthOf(64);
	});

	it('Проверка цифровой подписи хеша', async () => {
		const isVerified = nodeCryptopro.verifySignature(sourceMessageBytes, hashSignatureForSourceMessage, publicKeyBlob);

		expect(isVerified).to.equal(true);
	});

	it('Вычисление цифровой подписи предварительно подготовленного хеша', async () => {
		signatureForPreparedHash = nodeCryptopro.signPreparedHash(senderContainerName, hashForSourceMessage);

		expect(signatureForPreparedHash).to.have.lengthOf(64);
	});

	it('Проверка цифровой подписи предварительно подготовленного хеша', async () => {
		const responderPublicKeyBlob = publicKeyBlob;

		const isVerified = nodeCryptopro.verifyPreparedHashSignature(hashForSourceMessage, signatureForPreparedHash, responderPublicKeyBlob);

		expect(isVerified).to.equal(true);
	});

	it('Верификация подписи, созданной с помощью SignPreparedHash, функцией VerifySignature', async () => {
		const responderPublicKeyBlob = publicKeyBlob;

		const isVerified = nodeCryptopro.verifySignature(sourceMessageBytes, signatureForPreparedHash, responderPublicKeyBlob);

		expect(isVerified).to.equal(true);
	});

	it('Шифрование сообщения по алгоритму ГОСТ 28147', async () => {
		const responderPublicKeyBlob = publicKeyBlob;
		encryptionResult = nodeCryptopro.encrypt(sourceMessageBytes, senderContainerName, responderPublicKeyBlob);

		expect(encryptionResult.encryptedBytesArray).to.have.lengthOf(sourceMessageBytes.length);
		expect(encryptionResult.sessionKeyBlob).to.have.lengthOf(73);
		expect(encryptionResult.IV).to.have.lengthOf(8);
	});

	it('Дешифрование сообщения по алгоритму ГОСТ 28147', async () => {
		const senderPublicKeyBlob = publicKeyBlob;

		let decryptedBytes = nodeCryptopro.decrypt(
			encryptionResult.encryptedBytesArray, 
			responderContainerName,
			senderPublicKeyBlob,
			encryptionResult.IV,
			encryptionResult.sessionKeyBlob);

		const decryptedMessage = (new Buffer(decryptedBytes)).toString();

		expect(decryptedMessage).to.equal(sourceMessage);
	});

	it('Шифрование сообщения по алгоритму ГОСТ 28147 на готовом сессионном ключе', async () => {
		const responderPublicKeyBlob = publicKeyBlob;

		generatedSessionKey = nodeCryptopro.generateSessionKey(senderContainerName, responderPublicKeyBlob);

		encryptionResult2 = nodeCryptopro.encryptWithSessionKey(
			sourceMessageBytes, 
			senderContainerName, 
			responderPublicKeyBlob, 
			generatedSessionKey.sessionKeyBlob, 
			generatedSessionKey.IV
		);

		expect(encryptionResult2.encryptedBytesArray).to.have.lengthOf(sourceMessageBytes.length);
	});

	it('Дешифрование сообщения по алгоритму ГОСТ 28147 на готовом сессионном ключе', async () => {
		const senderPublicKeyBlob = publicKeyBlob;

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
		const oldResponderPublicKeyBlob = publicKeyBlob;
		const newResponderPublicKeyBlob = publicKeyBlob;

		let generatedSessionKey2 = nodeCryptopro.generateSessionKey(senderContainerName, oldResponderPublicKeyBlob);

		let result = nodeCryptopro.recodeSessionKey(
			generatedSessionKey2.sessionKeyBlob, 
			generatedSessionKey2.IV, 
			senderContainerName, 
			oldResponderPublicKeyBlob, 
			newResponderPublicKeyBlob);

		expect(1).to.equal(1);
	});

	it('Генерация сессионного ключа', async () => {
		const sessionKey = nodeCryptopro.generateSessionKey(senderContainerName, publicKeyBlob);

		expect(sessionKey.sessionKeyBlob).to.have.lengthOf(73);
		expect(sessionKey.IV).to.have.lengthOf(8);
	});

});