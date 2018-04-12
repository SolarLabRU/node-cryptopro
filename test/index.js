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

	const hashForSourceMessage = new Uint8Array([82,181,47,23,1,228,41,72,41,214,88,194,195,191,190,222,223,73,66,111,196,65,133,235,206,122,89,171,160,130,48,90]);


	const certificateSubjectKey = 'NewCert2012';

	let hashSignatureForSourceMessage = "";

	let publicKeyBlob = {};
	let encryptionResult = {};

	it('Вычисление хеша', async () => {
		const hash = nodeCryptopro.createHash(sourceMessageBytes);

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

		expect(hashSignatureForSourceMessage).to.have.lengthOf(64);
	});

	it('Проверка цифровой подписи хеша', async () => {
		const isVerified = nodeCryptopro.verifySignature(sourceMessageBytes, hashSignatureForSourceMessage, publicKeyBlob);

		expect(isVerified).to.equal(true);
	});

	it('Шифрование сообщения по алгоритму ГОСТ 28147', async () => {
		encryptionResult = nodeCryptopro.encrypt(sourceMessageBytes, senderContainerName, publicKeyBlob);

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

	it('Генерация сессионного ключа', async () => {
		const sessionKey = nodeCryptopro.generateSessionKey(senderContainerName, publicKeyBlob);
console.log(sessionKey);
		expect(sessionKey.sessionKeyBlob).to.have.lengthOf(73);
		expect(sessionKey.IV).to.have.lengthOf(8);
	});

});