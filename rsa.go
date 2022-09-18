package putty

import (
	"crypto/rsa"
	"fmt"
	"math/big"
)

func (k Key) readRSAPublicKey() (*rsa.PublicKey, error) {
	var pub struct {
		Header string   // header
		E      *big.Int // pub exponent
		N      *big.Int // pub modulus
	}
	_, err := unmarshal(k.PublicKey, &pub, false)
	if err != nil {
		return nil, err
	}

	if pub.Header != k.Algo {
		return nil, fmt.Errorf("invalid header inside public key: %q: expected %q", pub.Header, k.Algo)
	}

	publicKey := &rsa.PublicKey{
		E: int(pub.E.Int64()),
		N: pub.N,
	}

	return publicKey, nil
}

func (k *Key) setRSAPublicKey(pk *rsa.PublicKey) (err error) {
	var pub struct {
		Header string   // header
		E      *big.Int // pub exponent
		N      *big.Int // pub modulus
	}
	k.Algo = "ssh-rsa"
	pub.Header = "ssh-rsa"
	pub.E = big.NewInt(int64(pk.E))
	pub.N = pk.N
	k.PublicKey, _, err = marshal(&pub)
	return
}

func (k *Key) readRSAPrivateKey() (*rsa.PrivateKey, error) {
	publicKey, err := k.readRSAPublicKey()
	if err != nil {
		return nil, err
	}

	var priv struct {
		D    *big.Int // private exponent
		P1   *big.Int // prime 1
		P2   *big.Int // prime 2
		Qinv *big.Int // Qinv
	}
	k.keySize, err = unmarshal(k.PrivateKey, &priv, k.padded)
	if err != nil {
		return nil, err
	}

	privateKey := &rsa.PrivateKey{
		PublicKey: *publicKey,
		D:         priv.D,
		Primes: []*big.Int{
			priv.P1,
			priv.P2,
		},
		Precomputed: rsa.PrecomputedValues{
			Qinv: priv.Qinv,
		},
	}

	if err = privateKey.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %s", err)
	}

	privateKey.Precompute()

	// compare source and computed Qinv
	if priv.Qinv.Cmp(privateKey.Precomputed.Qinv) != 0 {
		return nil, fmt.Errorf("invalid precomputed data: %s", privateKey.Precomputed.Qinv)
	}

	return privateKey, nil
}

func (k *Key) setRSAPrivateKey(pk *rsa.PrivateKey) (err error) {
	err = k.setRSAPublicKey(&pk.PublicKey)
	if err != nil {
		return err
	}

	var priv struct {
		D    *big.Int // private exponent
		P1   *big.Int // prime 1
		P2   *big.Int // prime 2
		Qinv *big.Int // Qinv
	}

	priv.D = pk.D
	priv.P1 = pk.Primes[0]
	priv.P2 = pk.Primes[1]
	priv.Qinv = pk.Precomputed.Qinv
	k.PrivateKey, k.keySize, err = marshal(&priv)
	return
}
