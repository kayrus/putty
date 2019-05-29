package putty

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"strings"
)

func (k PuttyKey) readECDSA(password []byte) (interface{}, error) {
	var offset uint32
	// read the header
	header, err := readString(k.PublicKey, &offset)
	if err != nil {
		return nil, err
	}
	if header != k.Algo {
		return nil, fmt.Errorf("Invalid header inside public key: %q: expected %q", header, k.Algo)
	}

	// read ecdsa size
	algo, err := readString(k.PublicKey, &offset)
	if !strings.HasSuffix(k.Algo, algo) {
		return nil, fmt.Errorf("Elliptic curves algorythm %q doesn't correspond to %q", algo, k.Algo)
	}

	var curve elliptic.Curve
	switch algo {
	case "nistp256":
		curve = elliptic.P256()
	case "nistp384":
		curve = elliptic.P384()
	case "nistp521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("Unsupported elliptic curves algorythm %q", k.Algo)
	}

	qBytes, err := readBytes(k.PublicKey, &offset)
	if err != nil {
		return nil, err
	}
	xLength := len(qBytes) / 2
	x := new(big.Int).SetBytes(qBytes[1 : xLength+1])
	y := new(big.Int).SetBytes(qBytes[xLength+1:])

	// check public block size
	if len(k.PublicKey) != int(offset) {
		return nil, fmt.Errorf("Wrong public key size: got %d, expected %d", len(k.PublicKey), offset)
	}

	offset = 0
	priv, err := readBigInt(k.PrivateKey, &offset)
	if err != nil {
		return nil, err
	}

	err = k.checkGarbage(offset)
	if err != nil {
		return nil, err
	}

	curveOrder := curve.Params().N
	if priv.Cmp(curveOrder) >= 0 {
		return nil, fmt.Errorf("putty: invalid elliptic curve private key value")
	}

	// validate X and Y values
	pKey := make([]byte, (curveOrder.BitLen()+7)/8)
	copy(pKey[len(pKey)-len(priv.Bytes()):], priv.Bytes())
	xC, yC := curve.ScalarBaseMult(pKey)
	if x.Cmp(xC) != 0 {
		return nil, fmt.Errorf("calculated X doesn't correspond to public")
	}
	if y.Cmp(yC) != 0 {
		return nil, fmt.Errorf("calculated Y doesn't correspond to public")
	}

	privateKey := &ecdsa.PrivateKey{
		D: priv,
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
	}

	return privateKey, nil
}
