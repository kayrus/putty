# putty

![Test Status](https://github.com/kayrus/putty/actions/workflows/go-test.yml/badge.svg)
![Linter Status](https://github.com/kayrus/putty/actions/workflows/golangci-lint.yml/badge.svg)

Go package to parse PuTTY private key formats. Go 1.23 or above is required.

## Example - Reading PPK files

```go
package main

import (
	"log"

	"github.com/kayrus/putty"
)

func main() {
	var privateKey interface{}

	// read the key
	puttyKey, err := putty.NewFromFile("test.ppk")
	if err != nil {
		log.Fatal(err)
	}

	// parse putty key
	if puttyKey.Encryption != "none" {
		// If the key is encrypted, decrypt it
		privateKey, err = puttyKey.ParseRawPrivateKey([]byte("testkey"))
		if err != nil {
			log.Fatal(err)
		}
	} else {
		privateKey, err = puttyKey.ParseRawPrivateKey(nil)
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Printf("%+#v", privateKey)
}
```

## Example - Converting OpenSSH ED25519 key to PPK format

```go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/kayrus/putty"
)

func main() {
	// Generate or load an ED25519 private key
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
}
```
