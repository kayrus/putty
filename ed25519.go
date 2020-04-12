package putty

import (
	"crypto/ed25519"
	"fmt"
)

func (k Key) readED25519() (*ed25519.PrivateKey, error) {
	var pub struct {
		Header string
		Bytes  []byte
	}
	err := unmarshal(k.PublicKey, &pub, false)
	if err != nil {
		return nil, err
	}

	if pub.Header != k.Algo {
		return nil, fmt.Errorf("invalid header inside public key: %q: expected %q", pub.Header, k.Algo)
	}

	if len(pub.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key unexpected length: %d, expected %d", len(pub.Bytes), ed25519.PublicKeySize)
	}

	var priv []byte
	err = unmarshal(k.PrivateKey, &priv, k.Encryption != "none")
	if err != nil {
		return nil, err
	}

	var privateKey ed25519.PrivateKey
	privateKey = append(privateKey, priv...)
	privateKey = append(privateKey, pub.Bytes...)

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key unexpected length: %d, expected %d", len(privateKey), ed25519.PrivateKeySize)
	}

	return &privateKey, nil
}
