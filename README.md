# putty

Go package to parse PuTTY private key formats. Go 1.23 or above is required.

## Example

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
