package putty

import (
	"crypto/rsa"
	"fmt"
	"math/big"
)

func (k PuttyKey) readRSA(password []byte) (interface{}, error) {
	var offset uint32
	// read the header
	header, err := readString(k.PublicKey, &offset)
	if err != nil {
		return nil, err
	}
	if header != k.Algo {
		return nil, fmt.Errorf("Invalid header inside public key: %q: expected %q", header, k.Algo)
	}

	// pub exponent
	e, err := readBigInt(k.PublicKey, &offset)
	if err != nil {
		return nil, err
	}

	// pub modulus
	n, err := readBigInt(k.PublicKey, &offset)
	if err != nil {
		return nil, err
	}

	// check public block size
	if len(k.PublicKey) != int(offset) {
		return nil, fmt.Errorf("Wrong public key size: got %d, expected %d", len(k.PublicKey), offset)
	}

	offset = 0
	// private exponent
	d, err := readBigInt(k.PrivateKey, &offset)
	if err != nil {
		return nil, err
	}

	// prime 1
	p1, err := readBigInt(k.PrivateKey, &offset)
	if err != nil {
		return nil, err
	}

	// prime 2
	p2, err := readBigInt(k.PrivateKey, &offset)
	if err != nil {
		return nil, err
	}

	// Qinv
	qinv, err := readBigInt(k.PrivateKey, &offset)
	if err != nil {
		return nil, err
	}

	err = k.checkGarbage(offset)
	if err != nil {
		return nil, err
	}

	privateKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			E: int(e.Int64()),
			N: n,
		},
		D: d,
		Primes: []*big.Int{
			p1,
			p2,
		},
		Precomputed: rsa.PrecomputedValues{
			Qinv: qinv,
		},
	}

	if err = privateKey.Validate(); err != nil {
		return nil, fmt.Errorf("Validation failed: %s", err)
	}

	privateKey.Precompute()

	// compare source and computed Qinv
	if qinv.Cmp(privateKey.Precomputed.Qinv) != 0 {
		return nil, fmt.Errorf("Invalid precomputed data: %s")
	}

	return privateKey, nil
}
