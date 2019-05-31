package putty

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"math/big"
)

func (k Key) readRSA() (*rsa.PrivateKey, error) {
	buf := bytes.NewReader(k.PublicKey)

	// read the header
	header, err := readString(buf)
	if err != nil {
		return nil, err
	}

	if header != k.Algo {
		return nil, fmt.Errorf("invalid header inside public key: %q: expected %q", header, k.Algo)
	}

	// pub exponent
	e, err := readBigInt(buf)
	if err != nil {
		return nil, err
	}

	// pub modulus
	n, err := readBigInt(buf)
	if err != nil {
		return nil, err
	}

	// check public block size
	err = checkGarbage(buf, false)
	if err != nil {
		return nil, fmt.Errorf("wrong public key size: %s", err)
	}

	buf = bytes.NewReader(k.PrivateKey)

	// private exponent
	d, err := readBigInt(buf)
	if err != nil {
		return nil, err
	}

	// prime 1
	p1, err := readBigInt(buf)
	if err != nil {
		return nil, err
	}

	// prime 2
	p2, err := readBigInt(buf)
	if err != nil {
		return nil, err
	}

	// Qinv
	qinv, err := readBigInt(buf)
	if err != nil {
		return nil, err
	}

	err = checkGarbage(buf, k.Encryption != "none")
	if err != nil {
		return nil, fmt.Errorf("wrong private key size: %s", err)
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
		return nil, fmt.Errorf("validation failed: %s", err)
	}

	privateKey.Precompute()

	// compare source and computed Qinv
	if qinv.Cmp(privateKey.Precomputed.Qinv) != 0 {
		return nil, fmt.Errorf("invalid precomputed data: %s", privateKey.Precomputed.Qinv)
	}

	return privateKey, nil
}
