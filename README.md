# putty
Go package to parse PuTTY private key formats

## Example

```go
package main

import (
        "github.com/kayrus/putty"
        "log"
)

func main() {
        var privateKey interface{}
        var puttyKey putty.PuttyKey

        // read the key
        err := puttyKey.LoadFromFile("test.ppk")
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
