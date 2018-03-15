'use strict';

const nodeCryptopro = require('./nodeCryptopro');

const textToEncode = "text message to encode";


const senderContainerName = "5973e5bc6-1e43-6206-c603-21fdd08867e";
const responderCertFilename =  "2012_Cert.cer";

const responderContainerName = "5973e5bc6-1e43-6206-c603-21fdd08867e";
const senderCertFilename = "2012_Cert.cer";


const buffer = Buffer.from(textToEncode);

//Encrypt/Decrypt example
const bytesToEncrypt = new Uint8Array(buffer);
console.log("====Bytes to encode:" + bytesToEncrypt);

let encryptionResult = nodeCryptopro.encrypt(bytesToEncrypt, senderContainerName, responderCertFilename);

console.log("====encryptedBytesArray:" + encryptionResult.encryptedBytesArray);

console.log("====KeyBlob:" + encryptionResult.sessionKeyBlob);
console.log("====IV:" + encryptionResult.IV);


let encryptedBytesArray = new Uint8Array([46,44,243,89,248,138,192,196,23,58,255,75,75,92,8,14,121,132,206,97,219,124]);
let sessionKeyBlob = new Uint8Array([1,32,0,0,30,102,0,0,253,81,74,55,30,102,0,0,246,85,60,206,244,32,49,43,157,220,127,136,22,171,8,132,151,212,123,237,61,137,118,167,205,155,133,200,174,205,7,221,81,235,78,128,22,150,148,73,163,145,76,233,48,11,6,9,42,133,3,7,1,2,5,1,1]);
let IV = new Uint8Array([102,100,245,44,255,196,107,181]);

let decryptedBytes = nodeCryptopro.decrypt(
	encryptionResult.encryptedBytesArray, 
	responderContainerName,
	senderCertFilename,
	encryptionResult.IV,
	encryptionResult.sessionKeyBlob);

const decryptedMessage = (new Buffer(decryptedBytes)).toString();
console.log("Decrypted message:" + decryptedMessage);

//-------------------CryptoProKeyWrap
/*
let encryptedBytesArray = new Uint8Array([76,149,16,192,19,94,79,85,106,67,83,182,44,61,246,147,153,102,104,45,3,114]);

let blob = new Uint8Array([
1,32,0,0,30,102,0,0,253,81,74,55,30,102,0,0,
	140,29,137,127,121,245,125,179,
		77,89,113,132,96,50,150,35,226,43,47,186,238,169,235,137,27,58,69,127,189,139,248,2,237,223,247,82,179,202,92,119,12,24,18,44,
		48,9,6,7,42,133,3,2,2,31,1]);

let iv = new Uint8Array([59,133,22,139,66,152,166,35]);

let encryptedKey = new Uint8Array([77,89,113,132,96,50,150,35,226,43,47,186,238,169,235,137,27,58,69,127,189,139,248,2,237,223,247,82,179,202,92,119]);

let ParamSet = new Uint8Array([48,9,6,7,42,133,3,2,2,31,1]);//"1.2.643.2.2.31.1";

let Mac = new Uint8Array([12,24,18,44]);

let Ukm = new Uint8Array([140,29,137,127,121,245,125,179]);
//----------------------------------------
let decryptedBytes = nodeCryptopro.decrypt(
	encryptedBytesArray, 
	responderContainerName,
	senderCertFilename,
	iv,
	blob);

const decryptedMessage = (new Buffer(decryptedBytes)).toString();
console.log("Decrypted message:" + decryptedMessage);
*/

//Signature example:
/*const bytesArrayToSign = new Uint8Array(buffer);
console.log("Bytes to sign:" + bytesArrayToSign);


const signature = nodeCryptopro.signHash(senderContainerName, bytesArrayToSign);
console.log("Signature:" + signature);

//const signature = new Uint8Array([24,61,148,203,118,4,210,69,139,98,79,169,22,58,15,162,12,172,117,164,132,5,229,153,197,192,39,158,202,2,3,23,141,144,173,28,229,103,48,203,155,160,70,231,234,219,14,184,193,173,247,136,238,202,175,48,181,75,182,117,79,180,191,14]);
/*const isVerified = nodeCryptopro.verifySignature(bytesArrayToSign, signature, senderCertFilename);
if(isVerified) {
	console.log("Verified");
} else {
	console.log("Verification error");
}*/

//CreateHash example:
 //const hash = nodeCryptopro.createHash(bytesArrayToSign);
 //console.log("Hash:" + hash);
