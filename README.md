# putty

Go package to parse PuTTY private key formats. Go 1.13 or above is required.

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

  // init an empty public key with version 3
  outKey := putty.Key{Version: 3}

  // set the private key
  outKey.SetKey(privateKey)

  // print out the ppk file
  fmt.Printf("%s\n", outKey.Marshal())

	log.Printf("%+#v", privateKey)
}
```
