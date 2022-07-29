package ed25519tool

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

// Example of generating a public/private Ed25519 key pair, from a known
// seed (32 bytes of entropy). Debugging for other language implementations.
func Example_keyFromSeed() {
	seed := "65F65CCC43A8132AA303172D169F29A64D9D4E7BF0B701D109A58B9D048E35EF"
	seedBytes, err := hex.DecodeString(seed)
	if err != nil {
		fmt.Println(err)
	}
	pk := ed25519.NewKeyFromSeed(seedBytes)
	// Go's "private key" is the seed concatenated with public key.
	fmt.Printf("Seed: %X\n", pk[:32])
	fmt.Printf("Public Key: %X\n", pk[32:])

	// Output:
	//
	// Seed: 65F65CCC43A8132AA303172D169F29A64D9D4E7BF0B701D109A58B9D048E35EF
	// Public Key: A2BA5AEBC27D7FFB476E45CDEF00146EAABC2614EEB0B3A878541D96605E5A52
}
