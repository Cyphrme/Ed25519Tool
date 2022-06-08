# Ed25519 Applet

Live demo: https://cyphr.me/ed25519_applet/ed.html

## This tool can be run locally
In your web browser, use `file://` to load `ed.html`

```
file:///pathtodirectoy/ed.html
```

## Signing and verification tool for Ed25519


- Sign a message.
- Verify a signature.
- Generate a public key from seed.  
- Generate a new random public/private key pair and seed.

Supported formats:

Messages: Base64, Hex, and Text (Bytes).
Keys:     Base64 and Hex.



# Naming Differences in Implementations
Many libraries, including this tool, refer to what the RFC calls "private key" as the "seed" (like Go). The 32 byte seed is used to generate the private component, the public key, and the "prefix".
What some libraries call the "private key" (64 bytes) is the seed (32 bytes) concatenated with the public key (32 bytes). (Caching the public key precludes relatively slow regeneration when signing.)
The "actual" private component ("secret scalar s" as named by the RFC (Section 5.1.5.3)) is typically regenerated from seed on signing. The public component is computed from "secret scalar s", but the "prefix" (nounce) is generated from seed and is used for signing and is also typically regenerated on signing.
NaCL used to return the the private key as the "secret scalar s" with the "prefix". Instead of doing that most libraries simply regenerate both secret scalar s and prefix from seed, and optionally cache the public key.

# TODO
#### Ed25519ph
https://github.com/paulmillr/noble-ed25519/issues/63

Paul's Noble library currently only supports "PureEdDSA" and does not support
Ed25519ph ("pre-hashed").  We are waiting for it to be supported before we can
implement it. 


#### Generate from seed "secret scalar s" and permit input from `sss || prefix`
It would be nice to output `"secret scalar s" || "prefix"` and accept it as
input as well.  See https://github.com/paulmillr/noble-ed25519/issues/64.  It
would require additional code to Noble since sss || prefix is not a possible
input, assuming seed is not given.  

We  might never do this if there's no use for it among all modern tools.  


# Dist
`noble-ed25519.js` is taken directly from Noble and may be used in other
applications. See also `join.js`.

## Other ed25519 resources:

- https://ed25519.cr.yp.to/
- https://en.wikipedia.org/wiki/EdDSA
- https://ianix.com/pub/ed25519-deployment.html


# Attribution
Implemented using noble/ed25519: https://github.com/paulmillr/noble-ed25519

"Cyphr.me" is a trademark of Cypherpunk, LLC. The Cyphr.me logo is all rights
reserved Cypherpunk, LLC and may not be used without permission.

# Keywords
Ed25519 test page, Ed25519 online tool.  


