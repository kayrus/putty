package putty

import (
	"crypto/ed25519"
	"fmt"
)

func (k Key) readED25519PublicKey() (*ed25519.PublicKey, error) {
	var pub struct {
		Header string
		Bytes  []byte
	}
	_, err := unmarshal(k.PublicKey, &pub, false)
	if err != nil {
		return nil, err
	}

	if pub.Header != k.Algo {
		return nil, fmt.Errorf("invalid header inside public key: %q: expected %q", pub.Header, k.Algo)
	}

	if len(pub.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key unexpected length: %d, expected %d", len(pub.Bytes), ed25519.PublicKeySize)
	}

	return (*ed25519.PublicKey)(&pub.Bytes), nil
}

func (k *Key) setED25519PublicKey(pk *ed25519.PublicKey) (err error) {
	var pub struct {
		Header string
		Bytes  []byte
	}
	k.Algo = "ssh-ed25519"
	pub.Header = k.Algo
	pub.Bytes = ([]byte)(*pk)
	k.PublicKey, err = marshal(&pub)
	return
}

func (k *Key) readED25519PrivateKey() (*ed25519.PrivateKey, error) {
	publicKey, err := k.readED25519PublicKey()
	if err != nil {
		return nil, err
	}

	var priv []byte
	k.keySize, err = unmarshal(k.PrivateKey, &priv, k.padded)
	if err != nil {
		return nil, err
	}

	var privateKey ed25519.PrivateKey
	privateKey = append(privateKey, priv...)
	privateKey = append(privateKey, *publicKey...)

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key unexpected length: %d, expected %d", len(privateKey), ed25519.PrivateKeySize)
	}

	return &privateKey, nil
}

func (k *Key) setED25519PrivateKey(pk *ed25519.PrivateKey) (err error) {
	bytes := ([]byte)(*pk)
	cut := ed25519.PrivateKeySize - ed25519.PublicKeySize
	pub := bytes[cut:]
	err = k.setED25519PublicKey((*ed25519.PublicKey)(&pub))
	if err != nil {
		return err
	}

	priv := bytes[:cut]
	k.PrivateKey, err = marshal(&priv)
	k.keySize = len(k.PrivateKey)
	k.padded = false
	return
}
