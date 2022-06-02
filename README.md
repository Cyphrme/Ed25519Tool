# "Cyphr.me" is a trademark of Cypherpunk, LLC. The Cyphr.me logo is all rights reserved Cypherpunk, LLC and may not be used without permission.
# Cyphr.me Ed25519 Applet

See live demo here: https://cyphr.me/ed25519_applet/ed.html

## The applet is used as a signing and verification tool for ed25519.

The current supported formats are:

Base64, Hex, and Text for messages.
Base64 and Hex for ed25519 keys.

The tool can be used for the following:

Generate a new public private key pair from seed.
Generate a new random public private key pair.
Use an existing key.
Sign a message.
Verify a signature.

Please report any bugs under issues on the main Cyphr.me ed25519 applet github.

## Other ed25519 resources:

https://ed25519.cr.yp.to/
https://en.wikipedia.org/wiki/EdDSA
https://ianix.com/pub/ed25519-deployment.html


Implemented using noble/ed25519: https://github.com/paulmillr/noble-ed25519

# Development

When making changes to the JavaScript, be sure to rebuild the min file.
See join.js for more notes.
