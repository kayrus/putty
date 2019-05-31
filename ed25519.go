package putty

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/ed25519"
)

func (k Key) readED25519() (*ed25519.PrivateKey, error) {
	buf := bytes.NewReader(k.PublicKey)

	// read the header
	header, err := readString(buf)
	if err != nil {
		return nil, err
	}

	if header != k.Algo {
		return nil, fmt.Errorf("invalid header inside public key: %q: expected %q", header, k.Algo)
	}

	pub, err := readBytes(buf)
	if err != nil {
		return nil, err
	}

	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key unexpected length: %d, expected %d", len(pub), ed25519.PublicKeySize)
	}

	// check public block size
	err = checkGarbage(buf, false)
	if err != nil {
		return nil, fmt.Errorf("wrong public key size: %s", err)
	}

	buf = bytes.NewReader(k.PrivateKey)
	priv, err := readBytes(buf)
	if err != nil {
		return nil, err
	}

	err = checkGarbage(buf, k.Encryption != "none")
	if err != nil {
		return nil, fmt.Errorf("wrong private key size: %s", err)
	}

	var privateKey ed25519.PrivateKey
	privateKey = append(privateKey, priv...)
	privateKey = append(privateKey, pub...)

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key unexpected length: %d, expected %d", len(privateKey), ed25519.PrivateKeySize)
	}

	return &privateKey, nil
}
