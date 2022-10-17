"use strict";

/**
 * MSPPS holds the GUI values for the message, seed, key, and signature.
 * 
 * - Msg:      Msg in bytes, UTF-8 if relevant.
 * 
 * - SedHex:   Seed Hex.
 * - PubHex:   Public Key Hex.
 * - KypHex:   (Key Pair) Seed || Public Key.
 * - SigHex:   Signature Hex.
 * 
 * - Sed64:    Seed b64.
 * - Puk64:    Public Key b64.
 * - Kyp64:    (Key Pair) Seed || Public Key.  
 * - Sig64:    Signature b64.
 * 
 * - Sedb:     Seed bytes.
 * - Pukb:     Public Key
 * - Kypb:     (Key Pair) Seed || Public Key.  
 * - Sigb:     Signature.
 * @typedef  {{}}       MSPPS
 * @property {Uint8}    Msg
 * 
 * @property {Hex}      SedHex
 * @property {Hex}      PukHex 
 * @property {Hex}      KypHex
 * @property {Hex}      SigHex
 * 
 * @property {b64}      Sed64
 * @property {b64}      Puk64
 * @property {b64}      Kyp64
 * @property {b64}      Sig64
 * 
 * @property {Uint8}    Sedb
 * @property {Uint8}    Pukb
 * @property {Uint8}    Kypb
 * @property {Uint8}    Sigb
 */

// GUI Element variables
var InputMsg;
var MsgEncoding;
var EdType;
var KeyOptsElem;
var Seed;
var PublicKey;
var Signature;
var AppMessage;

// URLFormJS sticky form
let EdFormOptions = [{
	"name": "msg",
	"id": "InputMsg",
}, {
	"name": "msg_encoding",
	"id": "MsgEncoding",
}, {
	"name": "msg_type",
	"id": "EdType",
}, {
	"name": "key_encoding",
	"id": "KeyOpts"
}, {
	"name": "seed",
	"id": "Seed"
}, {
	"name": "key",
	"id": "PublicKey"
}, {
	"name": "sig",
	"id": "Signature"
}, ];


// DOM load
document.addEventListener('DOMContentLoaded', () => {
	URLForm.PopulateFromURI(URLForm.Init(EdFormOptions));

	InputMsg = document.getElementById('InputMsg');
	MsgEncoding = document.getElementById('MsgEncoding');
	EdType = document.getElementById('EdType');
	KeyOptsElem = document.getElementById('KeyOpts');
	Seed = document.getElementById('Seed');
	PublicKey = document.getElementById('PublicKey');
	Signature = document.getElementById('Signature');
	AppMessage = document.getElementById('AppMessage');


	// Set event listeners for buttons.
	document.getElementById('GenRandKeyPairBtn').addEventListener('click', GenRadomGUI);
	document.getElementById('GenKeyPairBtn').addEventListener('click', KeyFromSeed);
	document.getElementById('SignBtn').addEventListener('click', Sign);
	document.getElementById('VerifyBtn').addEventListener('click', Verify);
	document.getElementById('ClearBtn').addEventListener('click', ClearAll);
});

/**
 * GetMSPPS gets values from gui and returns MSPPS.
 * 
 * @returns  {MSPPS}        
 */
async function GetMSPPS() {
	/** @type {MSPPS} */
	let MSPPS = {};
	let Msg = InputMsg.value;

	switch (MsgEncoding.value) {
		case "B64":
			MSPPS.Msg = new Uint8Array(await HexToUI8(B64ToHex(Msg)));
			break;
		case "Hex":
			MSPPS.Msg = new Uint8Array(await HexToUI8(Msg));
			break;
		case "Text":
			let enc = new TextEncoder("utf-8"); // Suppose to be always in UTF-8.
			MSPPS.Msg = new Uint8Array(enc.encode(Msg));
			break;
		default:
			console.error('unsupported message encoding');
			return null;
	}

	if (EdType.value === "Dig") {
		// TODO, Support Ed25519ph
		console.error("Ed25519ph is currently not supported.")
	}

	let Sed = Seed.value;
	let Puk = PublicKey.value;
	let Sig = Signature.value;

	if (KeyOptsElem.value === "Hex") {
		MSPPS.SedHex = Sed;
		MSPPS.PukHex = Puk;
		MSPPS.KypHex = Sed + Puk;
		MSPPS.SigHex = Sig;
	}

	if (KeyOptsElem.value === "B64") {
		MSPPS.SedHex = B64ToHex(Sed);
		MSPPS.PukHex = B64ToHex(Puk);
		MSPPS.KypHex = B64ToHex(Sed) + B64ToHex(Puk);
		MSPPS.SigHex = B64ToHex(Sig);
	}

	if (isEmpty(MSPPS.SedHex)) {
		throw new SyntaxError("Private key is empty.")
	}
	if (MSPPS.SedHex.length == 128) {
		// Check if seed/private key is 64 bytes.  If so, assume `seed || public key`
		// and discard given public key.  
		MSPPS.SedHex = MSPPS.SedHex.slice(0, 64);
	}
	if (MSPPS.SedHex.length !== 64) {
		throw new SyntaxError("Seed is not 32 bytes.")
	}

	await SetMSPPSFromHex(MSPPS);
	if (isEmpty(MSPPS.Puk)) {
		KeyFromSeed(MSPPS);
	}

	return MSPPS;
}

/**
 * SetMSPPSFromHex sets the byte and base64 values from the Hex values.
 * Sets in place.
 * 
 * @param  {MSPPS} MSPPS
 */
async function SetMSPPSFromHex(MSPPS) {
	// console.log(MSPPS);
	MSPPS.Sed64 = await HexTob64ut(MSPPS.SedHex);
	MSPPS.Puk64 = await HexTob64ut(MSPPS.PukHex);
	MSPPS.Kyp64 = await HexTob64ut(MSPPS.KypHex);
	MSPPS.Sig64 = await HexTob64ut(MSPPS.SigHex);
	MSPPS.Sedb = await HexToUI8(MSPPS.SedHex);
	MSPPS.Pukb = await HexToUI8(MSPPS.PukHex);
	MSPPS.Kypb = await HexToUI8(MSPPS.KypHex);
	MSPPS.Sigb = await HexToUI8(MSPPS.SigHex);
}

/**
 * SetGuiIn sets the input GUI.
 * 
 * @param  {MSPPS} MSPPS
 */
function SetGuiIn(MSPPS) {
	if (KeyOptsElem.value === "Hex") {
		Seed.value = MSPPS.SedHex;
		PublicKey.value = MSPPS.PukHex;
		Signature.value = MSPPS.SigHex;
	}

	if (KeyOptsElem.value === "B64") {
		Seed.value = MSPPS.Sed64;
		PublicKey.value = MSPPS.Puk64;
		Signature.value = MSPPS.Sig64;
	}
}

/**
 * SetGuiOut sets the output GUI.
 * 
 * @param  {MSPPS} MSPPS
 */
async function SetGuiOut(MSPPS) {
	document.getElementById('SedHex').textContent = MSPPS.SedHex;
	document.getElementById('PukHex').textContent = MSPPS.PukHex;
	document.getElementById('KypHex').textContent = MSPPS.KypHex;
	document.getElementById('OSigHex').textContent = MSPPS.SigHex;
	document.getElementById('Sed64').textContent = MSPPS.Sed64;
	document.getElementById('Puk64').textContent = MSPPS.Puk64;
	document.getElementById('Kyp64').textContent = MSPPS.Kyp64;
	document.getElementById('OSig64').textContent = MSPPS.Sig64;
}

/**
 * GenRadomGUI generates a random seed, private key, and public key.
 * 
 * @returns  {void}
 */
async function GenRadomGUI() {
	let MSPPS = {};
	MSPPS.SedHex = await ArrayBufferToHex(await crypto.getRandomValues(new Uint8Array(32)));
	MSPPS.SigHex = "";
	AppMessage.textContent = "";
	await SetMSPPSFromHex(MSPPS);
	KeyFromSeed(MSPPS);
}

/**
 * KeyFromSeed gets from Gui and returns MSPPS
 * 
 * @param  {[MSPPS]} [MSPPS]    
 */
async function KeyFromSeed(MSPPS) {
	try {
		AppMessage.textContent = "";
		if (isEmpty(MSPPS.SedHex)) {
			MSPPS = await GetMSPPS();
		}
		// Ed25519 uses the lower 32 bytes of SHA-512
		// https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5
		let k = await window.nobleEd25519.utils.getExtendedPublicKey(MSPPS.Sedb);
		MSPPS.PukHex = k.point.toHex().toUpperCase();
		MSPPS.KypHex = MSPPS.SedHex + MSPPS.PukHex;
	} catch (error) {
		AppMessage.textContent = "❌ " + error;
		return;
	}

	await SetMSPPSFromHex(MSPPS);
	SetGuiIn(MSPPS);
	SetGuiOut(MSPPS);
}

/**
 * Sign signs the current input message, depending on selected encoding method.
 * 
 * @returns  {void}
 */
async function Sign() {
	try {
		Signature.value = "";
		var MSPPS = await GetMSPPS();
		if (MSPPS.Sedb === undefined) {
			throw new SyntaxError("Private key is empty.")
		}

		MSPPS.SigHex = await ArrayBufferToHex(await window.nobleEd25519.sign(MSPPS.Msg, MSPPS.Sedb));
		if (MSPPS.SigHex.length !== 128) { // Sanity check
			throw new RangeError("Invalid Signature length")
		}
	} catch (error) {
		AppMessage.textContent = "❌ " + error;
		return;
	}

	MSPPS.Sig64 = await HexTob64ut(MSPPS.SigHex);
	SetGuiIn(MSPPS);
	SetGuiOut(MSPPS);
}

/**
 * Verify verifies the current signature with the current message and public
 * key. Populates "#AppMessage" fail/success/error messages.
 * 
 * @returns  {void}
 */
async function Verify() {
	try {
		let MSPPS = await GetMSPPS();
		var valid = await window.nobleEd25519.verify(MSPPS.Sigb, MSPPS.Msg, MSPPS.Pukb);
	} catch (error) {
		console.error(error);
	}
	if (!valid) {
		AppMessage.textContent = "❌ Invalid Signature";
		return;
	}

	AppMessage.textContent = "✅ Valid Signature";
}

/**
 * ClearAll clears all GUI fields.
 * 
 * @returns  {void}
 */
async function ClearAll() {
	InputMsg.value = "";
	Seed.value = "";
	PublicKey.value = "";
	Signature.value = "";
	AppMessage.textContent = "";


	let MSPPS = await GetMSPPS();
	SetGuiIn(MSPPS);
	SetGuiOut(MSPPS);
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
 * @param   {string} hex    Hex representation.
 * @returns {string}        b64ut RFC 4648 URI safe truncated.
 */
async function HexTob64ut(hex) {
	let ab = await HexToUI8(hex);
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
 * 
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
 * @returns {string}       base64ut.
 */
function ArrayBufferTo64ut(buffer) {
	var string = String.fromCharCode.apply(null, new Uint8Array(buffer));
	return base64t(URIUnsafeToSafe(btoa(string)));
};


/**
 * HexToUI8 converts string Hex to UInt8Array. 
 * 
 * @param   {Hex}          Hex   String Hex.
 * @returns {Uint8Array}         ArrayBuffer.
 */
async function HexToUI8(hex) {
	if (hex === undefined) { // undefined is different from 0 since 0 == "AA"
		return new Uint8Array();
	}

	if ((hex.length % 2) !== 0) {
		throw new RangeError('HexToUI8: Hex is not even.')
	}

	var a = new Uint8Array(hex.length / 2)
	for (var i = 0; i < hex.length; i += 2) {
		a[i / 2] = parseInt(hex.substring(i, i + 2), 16)
	}

	return a;
};

/**
 * ArrayBufferToHex accepts an array buffer and returns a string of hex.
 * Taken from https://stackoverflow.com/a/50767210/1923095
 * 
 * @param   {ArrayBuffer} buffer     Buffer that is being converted to UTF8
 * @returns {string}                 String with hex.
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