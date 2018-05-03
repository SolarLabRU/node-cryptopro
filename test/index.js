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

//	console.log('sourceMessage: ' + buffer.toString('hex'));

	const hashForSourceMessage = new Uint8Array([82,181,47,23,1,228,41,72,41,214,88,194,195,191,190,222,223,73,66,111,196,65,133,235,206,122,89,171,160,130,48,90]);
	console.log("hashForSourceMessage: " + Buffer.from(hashForSourceMessage).toString('hex'));

	const publicKeyBytes = [144,129,142,86,169,62,26,195,207,130,70,122,105,84,35,108,162,39,114,195,205,130,86,214,24,187,179,50,178,170,134,15,82,165,222,213,0,31,89,235,98,208,30,89,111,242,79,159,234,213,149,143,34,11,145,117,195,31,87,82,221,2,83,139];
//	console.log("publicKeyBytesHex: " + Buffer.from(publicKeyBytes).toString('hex'));

	const certificateSubjectKey = 'NewCert2012';

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
		const certificateFilePath = './2012_Cert.cer';

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

/*		let pkBlob = new Uint8Array(101);
		pkBlob.set(publicKeyBlobHeader);
		pkBlob.set(pkBytes, publicKeyBlobHeader.length);

		let pkBlobMy = new Uint8Array(101);
		pkBlobMy.set(publicKeyBlobHeader);
		pkBlobMy.set(pkBytesMy, publicKeyBlobHeader.length);*/

		const hash = new Uint8Array( Buffer.from("52b52f1701e4294829d658c2c3bfbededf49426fc44185ebce7a59aba082305a", "hex") );
//		hash.reverse();
		const sign = new Uint8Array( Buffer.from("a9c3dd99a1a32007509fd083d7020e7888eaedfd6a1159caf5d15fac5048e91d57beb27770d8a2891aa297f6d64bcccfa598194c0bd181360913e5de0c1fd784", "hex") );

//		const sign = new Uint8Array( Buffer.from("82b2e64e518d7f492b36cd1fb9459374f42b5093e638f54cff4b6c0485c15930b6b80631fdc1356bbda00b3269891499e762839f7854ce34d2d05fdbce0515f9", "hex") );
//		const swapedSign = new Uint8Array( Buffer.from("9a8d38aa48cd2ab02e635860164cec9559d3903e32af019c1003b1c03280bc57a9e3f49ba1c4a64b8d7dc977e63e1625b1b7cb6369a00b81ea4c6ae9594b1334", "hex") );

//		const signMy = new Uint8Array( Buffer.from("254977ff23d4f04c5e5df7967bdad46bfc4a343bc7cb3caf6e7b4c293673ae4807d8d30e1da1305110486fb28ab6940f561ef2c2d66042fb3b9f7abae48417e6", "hex") );
//		const swapedSignMy = new Uint8Array( Buffer.from("e61784e4ba7a9f3bfb4260d6c2f21e560f94b68ab26f48105130a11d0ed3d80748ae7336294c7b6eaf3ccbc73b344afc6bd4da7b96f75d5e4cf0d423ff774925", "hex") );

//		const sign = nodeCryptopro.signPreparedHash(senderContainerName, hash);

		const isVerified = nodeCryptopro.verifyPreparedHashSignature(hash, sign, pkBytesN);

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

		let time = Date.now();

		generatedSessionKey = nodeCryptopro.generateSessionKey(senderContainerName, responderPublicKeyBlob);
		
		time = Date.now() - time;
		console.log('Время генерации сессионного ключа = ', time + " мс");

		let messageJSON = {
  "data": {
    "Id": "0626a968-e4eb-4497-95bf-ec3d4f635a1c",
    "FullName": "McGlynn - Hermiston",
    "ShortName": "Goyette and Sons",
    "Inn": "0000078396",
    "Kpp": "894750253",
    "Okopf": {
      "Code": "slead",
      "SingularName": "Mississippi"
    },
    "Ogrn": "3748313142801",
    "Ogrnip": "462002879316919",
    "RegistrationDate": "2018-04-20T13:25:07.2616421+03:00",
    "Okved": [
      {
        "Code": "iilrmaadee",
        "Name": "Wisconsin"
      },
      {
        "Code": "tobruidulr",
        "Name": "red"
      },
      {
        "Code": "liieieanua",
        "Name": "bypass"
      }
    ],
    "Okpo": "v1czviwip",
    "Oktmo": {
      "Code": "utrdtmbbotc",
      "Name": "Ford"
    },
    "Phone": "1-646-777-3285 x0370",
    "WebSite": "abdiel",
    "Fax": "283-591-5315",
    "EmailPublic": "Nickolas_Marks19@gmail.com",
    "Email": "Cristopher.Schroeder29@yahoo.com",
    "EmailAdditional": "Keely_White93@hotmail.com",
    "HeadFio": "Kuhic Tremayne",
    "ContactPerson": {
      "LastName": "Keeling",
      "FirstName": "Kylee",
      "MiddleName": "Kylee"
    },
    "AdditionalInformation": "Try to bypass the GB bandwidth, maybe it will bypass the open-source bandwidth!",
    "TimeZone": 7,
    "Smp": false,
    "Usn": true,
    "ContractMaxSum": 6605055028763018000,
    "Person": {
      "Id": "9d37f418-0f23-4d8d-8dd5-6078d60cd246",
      "LastName": "Torp",
      "FirstName": "Marlon",
      "MiddleName": "Marlon",
      "Position": "Mraz Inc",
      "Phone": "152.755.7587",
      "Email": "Marlon50.Torp48@hotmail.com",
      "Certificate": {
        "CertificateSn": "elaeiqnreaitnpurtetooonpdduatfuuarussons",
        "CertificateThumbprint": "iionivtbmfqixlpedmiuootuauqtaoeuaooeerre",
        "EsIssuerDn": "est",
        "EsIssuerSn": "eum",
        "PublicKey": "tatteetnmnmeuoanpatqtammttqusrrpduslqeen"
      }
    },
    "FactualAddress": {
      "Country": {
        "CountryCode": "FR",
        "CountryFullName": "Romania"
      },
      "Region": {
        "KladrType": "t",
        "KladrCode": "cxiumtk548",
        "FullName": "paradigm"
      },
      "Area": {
        "KladrType": "s",
        "KladrCode": "86w3m7kyu0",
        "FullName": "Metrics"
      },
      "City": {
        "KladrType": "e",
        "KladrCode": "ev74k8zkjf",
        "FullName": "firewall"
      },
      "Settlement": {
        "KladrType": "s",
        "KladrCode": "4wunpp21v6",
        "FullName": "Rubber"
      },
      "Street": {
        "KladrType": "p",
        "KladrCode": "2iwm56r916",
        "FullName": "Generic Frozen Chicken"
      },
      "PostCode": "43059-8912",
      "Building": "93300",
      "Office": "92650",
      "Okato": "i3ditvvni2"
    },
    "PostAddress": {
      "Country": {
        "CountryCode": "SE",
        "CountryFullName": "Hungary"
      },
      "Region": {
        "KladrType": "u",
        "KladrCode": "t02yi4bmc7",
        "FullName": "navigating"
      },
      "Area": {
        "KladrType": "v",
        "KladrCode": "66cb5myaq0",
        "FullName": "Tasty Steel Hat"
      },
      "City": {
        "KladrType": "o",
        "KladrCode": "5xzm6zxb3d",
        "FullName": "European Unit of Account 17(E.U.A.-17)"
      },
      "Settlement": {
        "KladrType": "l",
        "KladrCode": "ofluhbqh8r",
        "FullName": "relationships"
      },
      "Street": {
        "KladrType": "q",
        "KladrCode": "sj2tu52wen",
        "FullName": "hacking"
      },
      "PostCode": "02790",
      "Building": "5373",
      "Office": "04467",
      "Okato": "77npvijbv2",
      "FullAddress": "03072 Armstrong Ville, Lake Friedrich, Zimbabwe"
    },
    "BankDetails": {
      "Bik": "735780140",
      "PaymentAccount": "15856626509622030336",
      "CorrAccount": "10518542647603220480",
      "PersonalAccount": "11368402574848571392",
      "BankName": "Stamm Group",
      "BankAddress": "414 Cheyanne Expressway, South Marcelino, Kenya"
    },
    "Documents": {
      "Egrul": [],
      "ConstituentDocuments": [
        {
          "Id": "59fbc5e7-690c-412a-8a30-73166e48404b",
          "Name": "Optimization",
          "Size": 34655,
          "Url": "https://hazel.biz",
          "Actual": false,
          "Description": "Ea voluptatem reprehenderit fugiat distinctio doloribus eos dignissimos. Voluptatum dicta nobis et cum. Dolorem cupiditate eum vel eligendi consectetur mollitia. Repellendus in inventore sed sed nisi facere facilis architecto voluptatem.",
          "Date": "2017-05-24T02:53:55.6097157+03:00",
          "Sign": null
        },
        {
          "Id": "ab636396-0a74-46f6-a919-f2354d031abd",
          "Name": "Agent",
          "Size": 52496,
          "Url": "https://josianne.name",
          "Actual": true,
          "Description": "Voluptatibus a veniam aperiam eum. Eveniet saepe quis et tempore natus consequatur enim id iusto. Temporibus itaque aut dolorum fugiat perferendis nam.",
          "Date": "2017-05-17T21:27:55.5057608+03:00",
          "Sign": null
        },
        {
          "Id": "ada6dc7f-6fa2-49bd-8695-39b77a9d126b",
          "Name": "payment",
          "Size": 1592,
          "Url": "https://elton.biz",
          "Actual": true,
          "Description": "Aut dolorem fugit accusantium autem. Dignissimos vero enim dolorem ut. Consectetur facilis adipisci neque sint quo.",
          "Date": "2018-01-11T04:20:02.7202324+03:00",
          "Sign": null
        },
        {
          "Id": "85efdef3-9dfa-409c-86ae-6f0c7c1b959c",
          "Name": "Technician",
          "Size": 9616,
          "Url": "https://liliane.com",
          "Actual": true,
          "Description": "Ut veritatis deserunt modi ducimus quas voluptatem dolor quia. Esse et expedita omnis error nulla ipsam. Corrupti quae eum omnis reprehenderit animi qui.",
          "Date": "2018-03-13T15:32:10.775016+03:00",
          "Sign": null
        },
        {
          "Id": "fc25b548-c2eb-47d8-8d98-db7dbce80031",
          "Name": "Auto Loan Account",
          "Size": 57647,
          "Url": "http://valentine.biz",
          "Actual": true,
          "Description": "Quia sunt consequuntur itaque nobis eum esse voluptas nisi ullam. Ipsam voluptates qui aspernatur corporis et distinctio dolor. Non tempore asperiores. Nemo officiis in. Eum fuga consectetur deserunt dicta officiis ex enim consectetur rerum.",
          "Date": "2017-07-14T06:37:43.1333673+03:00",
          "Sign": null
        }
      ],
      "AccreditationAuthority": [
        {
          "Id": "c7dd86ad-14a1-4c50-93f4-68c056fe47d5",
          "Name": "functionalities",
          "Size": 3095,
          "Url": "http://jedidiah.net",
          "Actual": false,
          "Description": "Consectetur qui natus debitis non soluta sed culpa quae. Consequatur voluptatibus sint aut porro aut veritatis incidunt. Tempora dolorem fugit. Vero sint harum nostrum fuga optio deserunt atque sequi.",
          "Date": "2018-03-20T14:51:43.213587+03:00",
          "Sign": null
        },
        {
          "Id": "4f07b204-5484-4350-9260-b573e6363bd1",
          "Name": "Metal",
          "Size": 11306,
          "Url": "https://mikayla.name",
          "Actual": true,
          "Description": "Qui consequatur asperiores nobis eveniet voluptates voluptas consectetur. Deserunt nobis ab tenetur architecto deserunt. Commodi saepe reprehenderit repudiandae aut blanditiis ratione expedita. Qui consequatur unde deleniti nisi tempore nulla voluptate magni. At et eum id vel exercitationem quas dolorem saepe totam. Dolorem error culpa.",
          "Date": "2017-05-30T15:22:46.8736865+03:00",
          "Sign": null
        },
        {
          "Id": "37cc803e-91f3-4d7e-971b-b27601cffca2",
          "Name": "open-source",
          "Size": 52610,
          "Url": "https://ramona.net",
          "Actual": false,
          "Description": "Et ut dolor impedit vitae et voluptas facilis qui. Quod quo provident. Aut et vel nostrum. Consectetur autem incidunt aut delectus.",
          "Date": "2017-10-12T19:01:42.0070336+03:00",
          "Sign": null
        }
      ],
      "PowerOfAttorney": [
        {
          "Id": "c4e3dbbc-7255-4c06-a022-b3f087e1c32b",
          "Name": "Beauty",
          "Size": 21067,
          "Url": "http://yesenia.name",
          "Actual": true,
          "Description": "Excepturi autem vitae ut et nihil ut blanditiis quo. Dolorem molestias autem. Et in est qui accusantium.",
          "Date": "2018-01-25T01:52:16.8044023+03:00",
          "Sign": null
        },
        {
          "Id": "f91d3de0-d6f2-42a0-bb15-477e1da9dd5c",
          "Name": "transmitter",
          "Size": 10195,
          "Url": "http://teagan.net",
          "Actual": true,
          "Description": "Facere corporis occaecati sint dolorem aut officia quia veniam. Consequatur rerum ut magni totam dolorem dolores. Numquam necessitatibus aut eum. Voluptatibus ut aut optio quidem doloribus.",
          "Date": "2018-04-13T08:30:21.3819232+03:00",
          "Sign": null
        },
        {
          "Id": "f2243f91-ccc8-4861-bf84-e15a38e4f819",
          "Name": "compressing",
          "Size": 55432,
          "Url": "https://aryanna.net",
          "Actual": true,
          "Description": "Amet nulla consectetur quia culpa distinctio eum reprehenderit. Est molestiae quam omnis molestiae est rerum consequatur. Ut hic et ea hic eius tempora id vitae eaque. Ipsa soluta et et dolorum doloremque quae eligendi. Aut quia qui.",
          "Date": "2017-08-16T15:01:06.3092838+03:00",
          "Sign": null
        },
        {
          "Id": "a32117d5-a8eb-4ad1-bb44-23d858eadc5d",
          "Name": "Movies, Kids & Home",
          "Size": 23654,
          "Url": "http://marjorie.net",
          "Actual": false,
          "Description": "Natus dolor eveniet aut explicabo nulla in ut. Facilis aut veritatis excepturi non saepe error aliquam. Aut numquam consequatur aliquid reprehenderit. Sequi deserunt praesentium. Et aperiam voluptas vel aut ut veritatis magnam. Quisquam sapiente a placeat.",
          "Date": "2018-02-05T18:20:03.5364925+03:00",
          "Sign": null
        },
        {
          "Id": "73a201f4-a8a9-41c0-a5e3-13579c77c493",
          "Name": "Fantastic Frozen Chair",
          "Size": 8006,
          "Url": "http://jamil.net",
          "Actual": true,
          "Description": "Unde ad quia iure saepe illum quas iure at. Facilis ipsam adipisci sapiente dolore accusamus facilis. Sed ut voluptatem totam magni ipsam. Veritatis voluptatem rem.",
          "Date": "2018-03-22T04:10:44.1906661+03:00",
          "Sign": null
        }
      ],
      "HeadAuthority": [
        {
          "Id": "c68f9751-9e8c-4927-8f88-0bffe7e06377",
          "Name": "Rubber",
          "Size": 60341,
          "Url": "http://kaycee.org",
          "Actual": false,
          "Description": "Ut praesentium sunt eveniet eligendi. Illo maxime eaque officiis rem qui. Saepe inventore est beatae ratione. Commodi fugiat libero doloremque enim mollitia velit eaque qui qui. Aliquam sit omnis neque quidem rerum. Sunt iusto molestiae ut voluptatem fugit mollitia.",
          "Date": "2017-09-11T02:51:56.3170525+03:00",
          "Sign": null
        }
      ],
      "ApproveDecision": [
        {
          "Id": "e59ada07-34c4-41c2-8a10-30953c2cb5f4",
          "Name": "SMS",
          "Size": 56514,
          "Url": "http://jarrell.org",
          "Actual": false,
          "Description": "Incidunt molestiae corporis ullam minima aliquid. Id harum et blanditiis quae explicabo aliquam ipsum. Molestias impedit delectus. Sint omnis iusto et neque ut. Provident eligendi recusandae voluptate inventore.",
          "Date": "2018-01-22T17:11:44.4245643+03:00",
          "Sign": null
        },
        {
          "Id": "90e0c598-400e-4e37-8cb1-49141b0d43d5",
          "Name": "interface",
          "Size": 29991,
          "Url": "http://donny.com",
          "Actual": false,
          "Description": "Deleniti reiciendis amet iure omnis blanditiis est quam. Eos asperiores aut et soluta asperiores tempore dolores quod voluptatem. Voluptates cumque non. Assumenda ex at quo facere ut.",
          "Date": "2017-10-13T03:54:57.6865439+03:00",
          "Sign": null
        }
      ],
      "IdentityDocument": [
        {
          "Id": "a2070ebe-cc20-4cac-a76b-d5483126319e",
          "Name": "Licensed",
          "Size": 4728,
          "Url": "http://imani.net",
          "Actual": false,
          "Description": "Ad sapiente enim veritatis dolorem fugiat est laudantium animi. Esse unde amet aut. Assumenda repellendus dolorum nihil animi reiciendis nam minus qui. Doloremque aut est sed incidunt ea reiciendis. Veniam quidem id itaque. Id occaecati magni magnam voluptatem.",
          "Date": "2018-03-28T16:57:27.4219703+03:00",
          "Sign": null
        },
        {
          "Id": "cf46bbfc-089e-4a64-b444-e569b131db45",
          "Name": "Fresh",
          "Size": 58422,
          "Url": "https://edythe.net",
          "Actual": false,
          "Description": "Ad et est incidunt est. Dolores minus sed molestiae quis omnis. In et dolorem quae eum ducimus.",
          "Date": "2018-04-27T20:10:40.5662957+03:00",
          "Sign": null
        }
      ],
      "Others": [
        {
          "Id": "3b45d31b-7cda-4a08-9c81-fa2e49e5b1da",
          "Name": "Buckinghamshire",
          "Size": 33711,
          "Url": "https://imogene.net",
          "Actual": true,
          "Description": "Pariatur in sed rerum officiis. Accusantium molestias magnam aut rem temporibus. Quia dolor quia.",
          "Date": "2017-08-18T18:42:04.2389209+03:00",
          "Sign": null
        },
        {
          "Id": "c25187e7-8c6e-421d-a0c2-3d88ab98f134",
          "Name": "Way",
          "Size": 54362,
          "Url": "http://russell.biz",
          "Actual": true,
          "Description": "Eos explicabo deserunt et optio asperiores fuga et beatae. Sunt autem cupiditate corrupti eos ut culpa error perspiciatis. Praesentium ea minus. Id ipsam sequi ad architecto.",
          "Date": "2017-05-06T04:35:42.1175608+03:00",
          "Sign": null
        },
        {
          "Id": "8aea2d13-8b29-4b81-a36d-e2d416f61430",
          "Name": "streamline",
          "Size": 13315,
          "Url": "http://drake.org",
          "Actual": false,
          "Description": "Voluptatum dolorem non dolore. Placeat repudiandae sint dolores est cumque ad rerum mollitia voluptas. Id ea minima molestias eum.",
          "Date": "2017-06-30T23:38:02.1777329+03:00",
          "Sign": null
        },
        {
          "Id": "252d5262-a3f8-4871-86f8-cbeae2696967",
          "Name": "bricks-and-clicks",
          "Size": 5599,
          "Url": "http://johnathon.name",
          "Actual": true,
          "Description": "Et sunt eum quasi. Dolore nesciunt facere similique dolorem qui expedita officia autem porro. Laudantium debitis qui ut sunt quidem et et.",
          "Date": "2017-09-12T21:26:33.4883513+03:00",
          "Sign": null
        },
        {
          "Id": "809c2644-4d60-4436-b22a-67a607d80f33",
          "Name": "online",
          "Size": 10490,
          "Url": "https://davin.biz",
          "Actual": true,
          "Description": "Architecto cumque quaerat non vel aspernatur. Est quo soluta maiores sit omnis aliquid. Impedit quae quo est tempore. Doloribus architecto qui et magni possimus repellat velit.",
          "Date": "2018-01-03T11:39:21.170847+03:00",
          "Sign": null
        }
      ]
    },
    "PublicationDateTime": "2018-05-03T10:05:59.6899595+03:00"
  },
  "acls": [
  ]
};
		let messageString = JSON.stringify(messageJSON);

		let messageBytes = new Uint8Array( Buffer.from(messageString, 'utf8') );

		let timeInMs = Date.now();
		
		encryptionResult2 = await nodeCryptopro.encryptWithSessionKey(
			sourceMessageBytes, 
			senderContainerName, 
			responderPublicKeyBlob, 
			generatedSessionKey.sessionKeyBlob, 
			generatedSessionKey.IV
		);

		timeInMs = Date.now() - timeInMs;
		console.log('Время шифрования = ', timeInMs + " мс");

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