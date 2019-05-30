package putty

import (
	"fmt"

	"golang.org/x/crypto/ed25519"
)

func (k Key) readED25519(password []byte) (interface{}, error) {
	var offset uint32
	// read the header
	header, err := readString(k.PublicKey, &offset)
	if err != nil {
		return nil, err
	}
	if header != k.Algo {
		return nil, fmt.Errorf("Invalid header inside public key: %q: expected %q", header, k.Algo)
	}

	pub, err := readBytes(k.PublicKey, &offset)
	if err != nil {
		return nil, err
	}

	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key unexpected length: %d, expected %d", len(pub), ed25519.PublicKeySize)
	}

	// check public block size
	if len(k.PublicKey) != int(offset) {
		return nil, fmt.Errorf("Wrong public key size: got %d, expected %d", len(k.PublicKey), offset)
	}

	offset = 0
	priv, err := readBytes(k.PrivateKey, &offset)
	if err != nil {
		return nil, err
	}

	err = k.checkGarbage(offset)
	if err != nil {
		return nil, err
	}

	var privateKey ed25519.PrivateKey
	privateKey = append(privateKey, priv...)
	privateKey = append(privateKey, pub...)

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key unexpected length: %d, expected %d", len(privateKey), ed25519.PrivateKeySize)
	}

	return &privateKey, nil
}
