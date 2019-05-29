package putty

import (
	"crypto/dsa"
	"fmt"
)

func (k PuttyKey) readDSA(password []byte) (interface{}, error) {
	var offset uint32
	// read the header
	header, err := readString(&k.PublicKey, &offset)
	if err != nil {
		return nil, err
	}
	if header != k.Algo {
		return nil, fmt.Errorf("Invalid header inside public key: %q: expected %q", header, k.Algo)
	}

	p, err := readBigInt(&k.PublicKey, &offset)
	if err != nil {
		return nil, err
	}

	q, err := readBigInt(&k.PublicKey, &offset)
	if err != nil {
		return nil, err
	}

	g, err := readBigInt(&k.PublicKey, &offset)
	if err != nil {
		return nil, err
	}

	pub, err := readBigInt(&k.PublicKey, &offset)
	if err != nil {
		return nil, err
	}

	// check public block size
	if len(k.PublicKey) != int(offset) {
		return nil, fmt.Errorf("Wrong public key size: got %d, expected %d", len(k.PublicKey), offset)
	}

	offset = 0
	priv, err := readBigInt(&k.PrivateKey, &offset)
	if err != nil {
		return nil, err
	}

	err = k.checkGarbage(offset)
	if err != nil {
		return nil, err
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
