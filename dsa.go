package putty

import (
	"crypto/dsa"
	"fmt"
	"math/big"
)

func (k Key) readDSAPublicKey() (*dsa.PublicKey, error) {
	var pub struct {
		Header string
		P      *big.Int
		Q      *big.Int
		G      *big.Int
		Pub    *big.Int
	}
	_, err := unmarshal(k.PublicKey, &pub, false)
	if err != nil {
		return nil, err
	}

	if pub.Header != k.Algo {
		return nil, fmt.Errorf("invalid header inside public key: %q: expected %q", pub.Header, k.Algo)
	}

	publicKey := &dsa.PublicKey{
		Parameters: dsa.Parameters{
			P: pub.P,
			Q: pub.Q,
			G: pub.G,
		},
		Y: pub.Pub,
	}

	return publicKey, nil
}

func (k *Key) setDSAPublicKey(toSet *dsa.PublicKey) (err error) {
	var pub struct {
		Header string
		P      *big.Int
		Q      *big.Int
		G      *big.Int
		Pub    *big.Int
	}
	k.Algo = "ssh-dss"
	pub.Header = k.Algo
	pub.P = toSet.Parameters.P
	pub.Q = toSet.Parameters.Q
	pub.G = toSet.Parameters.G
	pub.Pub = toSet.Y
	k.PublicKey, err = marshal(&pub)
	return
}

func (k *Key) readDSAPrivateKey() (*dsa.PrivateKey, error) {
	publicKey, err := k.readDSAPublicKey()
	if err != nil {
		return nil, err
	}

	var priv *big.Int
	k.keySize, err = unmarshal(k.PrivateKey, &priv, k.padded)
	if err != nil {
		return nil, err
	}

	privateKey := &dsa.PrivateKey{
		PublicKey: *publicKey,
		X:         priv,
	}

	return privateKey, nil
}

func (k *Key) setDSAPrivateKey(pk *dsa.PrivateKey) (err error) {
	err = k.setDSAPublicKey(&pk.PublicKey)
	if err != nil {
		return err
	}

	var priv *big.Int
	priv = pk.X
	k.PrivateKey, err = marshal(&priv)
	k.keySize = len(k.PrivateKey)
	k.padded = false
	return
}
