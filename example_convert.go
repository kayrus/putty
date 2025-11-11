// +build ignore

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/kayrus/putty"
)

func main() {
	// Generate an ED25519 private key (or load from OpenSSH format)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	// Create a new PPK key structure with version 3
	outKey := putty.Key{Version: 3, Comment: "my-ed25519-key"}

	// Set the private key
	err = outKey.SetKey(&privateKey)
	if err != nil {
		log.Fatal(err)
	}

	// Marshal to PPK format
	ppkBytes, err := outKey.Marshal()
	if err != nil {
		log.Fatal(err)
	}

	// Print the PPK file content
	fmt.Printf("%s", ppkBytes)

	// Example output:
	// PuTTY-User-Key-File-3: ssh-ed25519
	// Encryption: none
	// Comment: my-ed25519-key
	// Public-Lines: 2
	// AAAAC3NzaC1lZDI1NTE5AAAAIMb3N9pbqMpSJRFb/WF8Wcz80SiW8emW3aLFqdRA
	// rs+r
	// Private-Lines: 1
	// i6a/aAknwkK/cVT8nW9zcsOJDvOdPvfBlx0suOtygmSbz9L4yoBAZZu8AHxWDSgm
	// Private-MAC: ...
}
