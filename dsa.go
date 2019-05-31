package putty

import (
	"bytes"
	"crypto/dsa"
	"fmt"
)

func (k Key) readDSA() (*dsa.PrivateKey, error) {
	buf := bytes.NewReader(k.PublicKey)

	// read the header
	header, err := readString(buf)
	if err != nil {
		return nil, err
	}

	if header != k.Algo {
		return nil, fmt.Errorf("invalid header inside public key: %q: expected %q", header, k.Algo)
	}

	p, err := readBigInt(buf)
	if err != nil {
		return nil, err
	}

	q, err := readBigInt(buf)
	if err != nil {
		return nil, err
	}

	g, err := readBigInt(buf)
	if err != nil {
		return nil, err
	}

	pub, err := readBigInt(buf)
	if err != nil {
		return nil, err
	}

	// check public block size
	err = checkGarbage(buf, false)
	if err != nil {
		return nil, fmt.Errorf("wrong public key size: %s", err)
	}

	buf = bytes.NewReader(k.PrivateKey)

	priv, err := readBigInt(buf)
	if err != nil {
		return nil, err
	}

	err = checkGarbage(buf, k.Encryption != "none")
	if err != nil {
		return nil, fmt.Errorf("wrong private key size: %s", err)
	}

	privateKey := &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: p,
				Q: q,
				G: g,
			},
			Y: pub,
		},
		X: priv,
	}

	return privateKey, nil
}
