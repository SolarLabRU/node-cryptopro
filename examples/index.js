'use strict';

const nodeCryptopro = require('node-cryptopro');

const senderContainerName = "5973e5bc6-1e43-6206-c603-21fdd08867e";
const responderCertFilename =  "2012_Cert.cer";

const responderContainerName = "5973e5bc6-1e43-6206-c603-21fdd08867e";
const senderCertFilename = "2012_Cert.cer";


const textToEncode = "text message to encode";
const buffer = Buffer.from(textToEncode);


//Encrypt/Decrypt example
const bytesToEncrypt = new Uint8Array(buffer);
console.log("Bytes to encode:" + bytesToEncrypt);

let encryptionResult = nodeCryptopro.encrypt(bytesToEncrypt, senderContainerName, responderCertFilename);

console.log("encryptedBytesArray:" + encryptionResult.encryptedBytesArray);
console.log("KeyBlob:" + encryptionResult.sessionKeyBlob);
console.log("IV:" + encryptionResult.IV);

let decryptedBytes = nodeCryptopro.decrypt(
	encryptionResult.encryptedBytesArray, 
	responderContainerName,
	senderCertFilename,
	encryptionResult.IV,
	encryptionResult.sessionKeyBlob);

const decryptedMessage = (new Buffer(decryptedBytes)).toString();
console.log("Decrypted message:" + decryptedMessage);


//Signature example:
const bytesArrayToSign = new Uint8Array(buffer);
console.log("Bytes to sign:" + bytesArrayToSign);

const signature = nodeCryptopro.signHash(senderContainerName, bytesArrayToSign);
console.log("Signature:" + signature);

const isVerified = nodeCryptopro.verifySignature(bytesArrayToSign, signature, senderCertFilename);
if(isVerified) {
	console.log("Verified");
} else {
	console.log("Verification error");
}

//CreateHash example:
const hash = nodeCryptopro.createHash(bytesArrayToSign);
console.log("Hash:" + hash);
