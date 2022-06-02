"use strict";

import * as ed from './noble-ed25519.js';

export {
	GenRadomKeyPairGUI,
	KeyFromSeedGUI,
	SignMsgGUI,
	VerifySigGUI,
}

// GUI Element variables
//
// Key encoding formats (e.g. "Hex" or "B64")
var KeyOptsElem;

// DOM load
document.addEventListener('DOMContentLoaded', () => {
	KeyOptsElem = document.getElementById('KeyOpts');

	// Set event listeners for buttons.
	document.getElementById('GenRandKeyPairBtn').addEventListener('click', GenRadomKeyPairGUI);
	document.getElementById('GenKeyPairBtn').addEventListener('click', KeyFromSeedGUI);
	document.getElementById('SignBtn').addEventListener('click', SignMsgGUI);
	document.getElementById('VerifyBtn').addEventListener('click', VerifySigGUI);
});

// Generates a new public private key pair, and sets the seed, private key, and
// public key for the GUI In and Out sections.
async function GenRadomKeyPairGUI() {
	let seed = crypto.getRandomValues(new Uint8Array(32));
	let hex = await ArrayBufferToHex(seed);
	if (KeyOptsElem.value === "Hex") {
		seed = hex;
	} else {
		seed = await ArrayBufferTo64ut(seed);
	}
	// console.debug(seed)
	await setSeedGUI(seed);
	setKeyPairGUIFromHex(await HashHex("SHA-256", hex));
}

// Generates an ed25519 public private key pair. Both outputs in the GUI will be
// set, as well as setting the Input key pair (In the selected encoding).
async function KeyFromSeedGUI() {
	let seed = document.getElementById('Seed').value;
	if (isEmpty(seed)) {
		console.debug('Seed is empty... seeing if private key is already set.');
		let pk = await getPrivateKeyBytes();
		console.debug(pk)
		if (pk === null) {
			return;
		}

		return;
	}
	await setSeedGUI(seed);
	if (KeyOptsElem.value !== "Hex") {
		seed = B64ToHex(seed);
	}
	setKeyPairGUIFromHex(await HashHex("SHA-256", seed));
}

// Signs the current input message, depending on selected encoding method.
async function SignMsgGUI() {
	let privateKeyBytes = await getPrivateKeyBytes();
	let msgBytes = await getMessageBytes();
	if (privateKeyBytes === null || msgBytes === null) {
		// console.debug("private key or message is null.");
		return;
	}
	// Sets both application and GUI signature values.
	let bytes = await ed.sign(msgBytes, privateKeyBytes);
	if (!ed25519SigLenCheck(bytes)) {
		return;
	}
	let Hex = await ArrayBufferToHex(bytes);

	// console.debug(Hex);
	if (isEmpty(Hex) || Hex.length % 2 === 1) {
		console.error('input is invalid Hex');
		return;
	}

	document.getElementById("HexSig").textContent = Hex;
	document.getElementById('B64Sig').textContent = await HexTob64ut(Hex);
	setElemFromHex(document.getElementById('Signature'), Hex);
}

// Verifies the current signature with the current message and public key.
// Populates the ValidSignature span with the fail/success message.
async function VerifySigGUI() {
	let valid = false;
	let msg = "Invalid Signature";
	let sig = document.getElementById('Signature').value;
	let signatureBytes = await getSignatureBytes();
	if (!isEmpty(sig) && ed25519SigLenCheck(signatureBytes)) {
		try {
			// console.debug(signatureBytes, await getMessageBytes(), await getPublicKeyBytes());
			valid = await ed.verify(signatureBytes, await getMessageBytes(), await getPublicKeyBytes());
		} catch (error) {
			console.error(error);
			valid = false;
		} finally {
			if (valid) {
				msg = "Valid Signature";
			}
			// console.debug(valid);
		}
	}
	document.getElementById('ValidSignature').textContent = msg;
}


///////////////////////////////////////////////
//////////////////  Helpers  //////////////////
///////////////////////////////////////////////

// Sets the GUI In and Out sections' public private key pair values.
async function setKeyPairGUIFromHex(Hex) {
	let privB64 = await HexTob64ut(Hex);
	let pubHex = await ArrayBufferToHex(await ed.getPublicKey(new Uint8Array(await HexToArrayBuffer(Hex))));
	let pubB64 = await HexTob64ut(pubHex);
	// Sets private key outputs
	document.getElementById('HexPriKey').textContent = Hex;
	document.getElementById('B64PriKey').textContent = privB64;
	// Sets public key outputs.
	document.getElementById('HexPubKey').textContent = pubHex;
	document.getElementById('B64PubKey').textContent = pubB64;

	// Sets key pair for inputs.
	let priv;
	let pub;
	if (KeyOptsElem.value === "Hex") {
		priv = Hex;
		pub = pubHex;
	} else {
		priv = privB64;
		pub = pubB64;
	}
	// Sets main public private key pair in the GUI In section.
	document.getElementById('PublicKey').value = pub;
	document.getElementById('PrivateKey').value = priv;
}

// Returns an UInt8Array of the current Private Key in the GUI.
// If the private key is not populated, function errors and returns null.
async function getPrivateKeyBytes() {
	let PrivateKey = document.getElementById('PrivateKey').value;
	if (isEmpty(PrivateKey)) {
		console.error('Private key is empty.');
		return null;
	}
	if (KeyOptsElem.value !== "Hex") {
		PrivateKey = B64ToHex(PrivateKey);
	}
	return new Uint8Array(await HexToArrayBuffer(PrivateKey));
}

// Returns an UInt8Array of the current Public Key in the GUI.
// If the public key is not populated, the public key will attempt to be derived
// from the seed, or private key. If both are empty, fails and returns null.
async function getPublicKeyBytes() {
	let PublicKey = document.getElementById('PublicKey').value;
	if (isEmpty(PublicKey)) {
		console.debug('PublicKey is empty... Attempting to derive from private key.');
		let PrivateKey = document.getElementById('PrivateKey').value;
		if (isEmpty(PrivateKey)) {
			console.debug('PrivateKey is empty... Attempting to derive from the seed.');
			let seed = document.getElementById('Seed').value;
			if (isEmpty(seed)) {
				console.error('Seed is empty.');
				return null;
			} else {
				if (KeyOptsElem.value !== "Hex") {
					seed = B64ToHex(seed);
				}
				PublicKey = await ArrayBufferToHex(await getPubKeyBytesFromPrivateKeyString(await HashHex("SHA-256", seed)));
			}
		} else {
			PublicKey = await ArrayBufferToHex(await getPubKeyBytesFromPrivateKeyString(PrivateKey));
		}
	}

	if (KeyOptsElem.value !== "Hex") {
		PublicKey = B64ToHex(PublicKey);
	}
	return new Uint8Array(await HexToArrayBuffer(PublicKey));
}

// Returns a UInt8Array of the public key, from the private key string.
async function getPubKeyBytesFromPrivateKeyString(string) {
	let bytes;
	if (KeyOptsElem.value === "Hex") {
		bytes = await HexToArrayBuffer(string);
	} else {
		bytes = await HexToArrayBuffer(B64ToHex(string));
	}
	return await ed.getPublicKey(new Uint8Array(bytes));
}

// Returns a UInt8Array of the current Signature in the GUI.
// If the signature is not populated, fails and returns null.
async function getSignatureBytes() {
	let Signature = document.getElementById('Signature').value;
	if (isEmpty(Signature)) {
		console.error('Signature is empty.');
		return null;
	}
	if (KeyOptsElem.value !== "Hex") {
		Signature = B64ToHex(Signature);
	}
	return new Uint8Array(await HexToArrayBuffer(Signature));
}

// Returns a UInt8Array of the current message in the GUI.
// If message is empty, an empty UInt8Array will be returned.
async function getMessageBytes() {
	let Message = document.getElementById('InputMsg').value;
	let messageBytes = new Uint8Array(); // Empty message is valid.

	// console.debug(Message);
	if (!isEmpty(Message)) {
		switch (document.getElementById('MsgOpts').value) {
			case "B64":
				messageBytes = new Uint8Array(await HexToArrayBuffer(B64ToHex(Message)));
				break;
			case "Hex":
				messageBytes = new Uint8Array(await HexToArrayBuffer(Message));
				break;
			case "Text":
				let enc = new TextEncoder("utf-8"); // Suppose to be always in UTF-8.
				messageBytes = enc.encode(Message);
				break;
			default:
				console.error('unsupported message encoding');
				return null;
		}
	}
	return messageBytes;
}

// Sets all of the seed values in the GUI from the given seed string.
// Key encoding must be set accordingly to the passed seed, before calling this
// function.
async function setSeedGUI(seed) {
	let b64Seed;
	let hexSeed;
	if (KeyOptsElem.value !== "Hex") {
		b64Seed = seed;
		seed = B64ToHex(seed);
		hexSeed = seed;
	} else {
		hexSeed = seed;
		b64Seed = await HexTob64ut(seed);
	}
	// console.debug(b64Seed, hexSeed, seed);

	document.getElementById('B64Seed').textContent = b64Seed;
	document.getElementById('HexSeed').textContent = hexSeed;
	setElemFromHex(document.getElementById('Seed'), seed);
}

// Sets the given element's value with the given Hex value, based on the selected
// Key Options.
// Will not work if the given element is a span. .textContent instead of .value
// is needed for spans.
async function setElemFromHex(elem, Hex) {
	// console.debug(elem, Hex);
	if (KeyOptsElem.value === "Hex") {
		elem.value = Hex;
		return;
	}
	elem.value = await HexTob64ut(Hex);
}

// Returns false if the byte length is incorrect, and true with correct length.
function ed25519SigLenCheck(bytes) {
	if (isEmpty(bytes.byteLength) || bytes.byteLength !== 64) {
		console.error("Invalid Signature length");
		return false;
	}
	return true;
}


////////////////////////////////
// Taken from Cyphrme Lib
////////////////////////////////

/**
 * B64ToHex takes any RFC 4648 base64 to Hex.
 * 
 * @param    {string} b64        RFC 4648 any base64.
 * @returns  {string}            Hex representation.
 */
function B64ToHex(b64) {
	//  console.debug(b64);
	let ub64 = URISafeToUnsafe(b64);
	const raw = atob(ub64);
	let result = '';
	for (let i = 0; i < raw.length; i++) {
		const hex = raw.charCodeAt(i).toString(16).toUpperCase();
		result += (hex.length === 2 ? hex : '0' + hex);
	}
	return result;
};

/**
 * URISafeToUnsafe converts any URI safe string to URI unsafe.  
 * 
 * @param   {string} b64ut 
 * @returns {string} ub64t
 */
function URISafeToUnsafe(ub64) {
	return ub64.replace(/-/g, '+').replace(/_/g, '/');
};

/**
 * HexTob64ut is hex to "RFC 4648 URI Safe Truncated".  
 * 
 * @param   {string} hex    String. Hex representation.
 * @returns {string}        String. b64ut RFC 4648 URI safe truncated.
 */
async function HexTob64ut(hex) {
	let ab = await HexToArrayBuffer(hex);
	return await ArrayBufferTo64ut(ab);
};

/**
 * URIUnsafeToSafe converts any URI unsafe string to URI safe.  
 * 
 * @param   {string} ub64t 
 * @returns {string} b64ut 
 */
function URIUnsafeToSafe(ub64) {
	return ub64.replace(/\+/g, '-').replace(/\//g, '_');
};

/**
 * base64t removes base64 padding if applicable.
 * @param   {string} base64 
 * @returns {string} base64t
 */
function base64t(base64) {
	return base64.replace(/=/g, '');
}

/**
 * ArrayBufferTo64ut Array buffer to b64ut.
 * 
 * @param   {ArrayBuffer}  buffer 
 * @returns {string}       String. base64ut.
 */
function ArrayBufferTo64ut(buffer) {
	var string = String.fromCharCode.apply(null, new Uint8Array(buffer));
	return base64t(URIUnsafeToSafe(btoa(string)));
};

// Returns the digest (in Hex) from the given Hex input and hash alg. Throws.
async function HashHex(hashAlg, Hex) {
	// console.debug(hashAlg, input);
	if (isEmpty(hashAlg)) {
		throw new Error("No hash algorithm specified");
	}
	return ArrayBufferToHex(await crypto.subtle.digest(hashAlg, await HexToArrayBuffer(Hex)));
}

/**
 * Taken from https://github.com/LinusU/hex-to-array-buffer  MIT license
 * @param   {string} Hex         String. Hexrepresentation
 * @returns {ArrayBuffer}        ArrayBuffer. 
 */
async function HexToArrayBuffer(hex) {
	if (typeof hex !== 'string') {
		// console.debug(typeof hex);
		throw new TypeError('base_convert.HexToArrayBuffer: Expected input to be a string')
	}

	if ((hex.length % 2) !== 0) {
		throw new RangeError('base_convert.HexToArrayBuffer: Expected string to be an even number of characters')
	}

	var view = new Uint8Array(hex.length / 2)

	for (var i = 0; i < hex.length; i += 2) {
		view[i / 2] = parseInt(hex.substring(i, i + 2), 16)
	}

	return view.buffer
};

/**
 * ArrayBufferToHex accepts an array buffer and returns a string of hex.
 * Taken from https://stackoverflow.com/a/50767210/1923095
 * 
 * @param {ArrayBuffer} buffer       str that is being converted to UTF8
 * @returns {string} hex             String with hex.  
 */
async function ArrayBufferToHex(buffer) {
	return [...new Uint8Array(buffer)].map(x => x.toString(16).padStart(2, "0")).join('').toUpperCase();

	// Alternatively:
	// let hashArray = Array.from(new Uint8Array(digest)); // convert buffer to byte array
	// let hexHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

/**
 * isEmpty is a helper function to determine if thing is empty. 
 * 
 * Objects are empty if they have no keys. (Returns len === 0 of object keys.)
 *
 * Functions are considered always not empty. 
 * 
 * NaN returns true.  (NaN === NaN is always false, as NaN is never equal to
 * anything. NaN is the only JavaScript value unequal to itself.)
 *
 * Don't use on HTMl elements. For HTML elements, use the !== equality check
 * (element !== null).
 *
 * Cannot use CryptoKey with this function since (len === 0) always. 
 *
 * @param   {any}     thing    Thing you wish was empty.  
 * @returns {boolean}          Boolean.  
 */
function isEmpty(thing) {
	if (typeof thing === 'function') {
		return false;
	}

	if (thing === Object(thing)) {
		if (Object.keys(thing).length === 0) {
			return true;
		}
		return false;
	}

	if (!isBool(thing)) {
		return true;
	}
	return false
};

/**
 * Helper function to determine boolean.  
 *
 * Javascript, instead of considering everything false except a few key words,
 * decided everything is true instead of a few key words.  Why?  Because
 * Javascript.  This function inverts that assumption, so that everything can be
 * considered false unless true. 
 *
 * @param   {any}      bool   Thing that you wish was a boolean.  
 * @returns {boolean}         An actual boolean.  
 */
function isBool(bool) {
	if (
		bool === false ||
		bool === "false" ||
		bool === undefined ||
		bool === "undefined" ||
		bool === "" ||
		bool === 0 ||
		bool === "0" ||
		bool === null ||
		bool === "null" ||
		bool === "NaN" ||
		Number.isNaN(bool) ||
		bool === Object(bool) // isObject
	) {
		return false;
	}
	return true;
};