# Ed25519 Applet

Live demo: https://cyphr.me/ed25519_applet/ed.html

## Signing and verification tool for Ed25519

The tool can:

- Sign a message.
- Verify a signature.
- Generate a new public/private key pair from seed.
- Generate a public key from private key.  
- Generate a new random public/private key pair and seed.
- Use an existing key.

Supported formats:

Messages: Base64, Hex, and Text (Bytes).
Keys:     Base64 and Hex.

# Terminology
This package does not use the RFC's terminology, nor do other popular libraries,
like https://pkg.go.dev/crypto/ed25519 or
https://github.com/dchest/tweetnacl-js.  


This packages's

- "seed" is the RFC's "private key"
- "Private key" is the RFC's "scalar s"
- "Public key" is the RFC's "public key"


# TODO
## Ed25519ph
https://github.com/paulmillr/noble-ed25519/issues/63

Paul's Noble library currently only supports "PureEdDSA" and does not support
Ed25519ph (Ed25519 post hash aka pre-hashed).  We are waiting for it to be
supported before we can implement it. 



## Generation from Seed
https://github.com/paulmillr/noble-ed25519/issues/64

Waiting for generation from seed.  


# Development

When making changes to the JavaScript, be sure to rebuild the `ed.min.js`.
See `join.js` for more notes.

## Other ed25519 resources:

- https://ed25519.cr.yp.to/
- https://en.wikipedia.org/wiki/EdDSA
- https://ianix.com/pub/ed25519-deployment.html


# Attribution
Implemented using noble/ed25519: https://github.com/paulmillr/noble-ed25519

"Cyphr.me" is a trademark of Cypherpunk, LLC. The Cyphr.me logo is all rights
reserved Cypherpunk, LLC and may not be used without permission.








```Javascript
// Gets values from GUI and returns MSPPS with Msg in Uint8 and everything else Hex. 
async function GetMSPPSHex() {
	var MSPPS = {};
	MSPPS.Msg = document.getElementById('InputMsg').value;
	MSPPS.Sed = document.getElementById('Seed').value;
	MSPPS.Prk = document.getElementById('PrivateKey').value;
	MSPPS.Puk = document.getElementById('PublicKey').value;
	MSPPS.Sig = document.getElementById('Signature').value;

	if (KeyOptsElem.value === "B64") {
		MSPPS.Sed = B64ToHex(MSPPS.Sed);
		MSPPS.Prk = B64ToHex(MSPPS.Prk);
		MSPPS.Puk = B64ToHex(MSPPS.Puk)
		MSPPS.Sig = B64ToHex(MSPPS.Sig)
	}

	let messageBytes = new Uint8Array(); // Empty message is valid.

	// TODO Our functions should not break on empty.  Look into this.  
	if (!isEmpty(MSPPS.Msg)) {
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
	MSPPS.Msg = messageBytes;

	return MSPPS;
}

async function SanMSPPS {

}


async function SetMSPPS {

}
async function SetOut {

}
```