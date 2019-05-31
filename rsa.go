package putty

import (
	"crypto/rsa"
	"fmt"
	"math/big"
)

func (k Key) readRSA() (*rsa.PrivateKey, error) {
	var pub struct {
		Header string   // header
		E      *big.Int // pub exponent
		N      *big.Int // pub modulus
	}
	err := unmarshal(k.PublicKey, &pub, false)
	if err != nil {
		return nil, err
	}

	if pub.Header != k.Algo {
		return nil, fmt.Errorf("invalid header inside public key: %q: expected %q", pub.Header, k.Algo)
	}

	var priv struct {
		D    *big.Int // private exponent
		P1   *big.Int // prime 1
		P2   *big.Int // prime 2
		Qinv *big.Int // Qinv
	}
	err = unmarshal(k.PrivateKey, &priv, k.Encryption != "none")
	if err != nil {
		return nil, err
	}

	privateKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			E: int(pub.E.Int64()),
			N: pub.N,
		},
		D: priv.D,
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
