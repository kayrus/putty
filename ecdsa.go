package putty

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"strings"
)

func (k Key) readECDSA() (*ecdsa.PrivateKey, error) {
	buf := bytes.NewReader(k.PublicKey)

	// read the header
	header, err := readString(buf)
	if err != nil {
		return nil, err
	}

	if header != k.Algo {
		return nil, fmt.Errorf("invalid header inside public key: %q: expected %q", header, k.Algo)
	}

	// read ecdsa key length
	length, err := readString(buf)
	if !strings.HasSuffix(k.Algo, length) {
		return nil, fmt.Errorf("elliptic curves %q key length doesn't correspond to %q", length, k.Algo)
	}

	var curve elliptic.Curve
	switch length {
	case "nistp256":
		curve = elliptic.P256()
	case "nistp384":
		curve = elliptic.P384()
	case "nistp521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported elliptic curves key length %q", length)
	}

	qBytes, err := readBytes(buf)
	if err != nil {
		return nil, err
	}

	xLength := len(qBytes) / 2
	x := new(big.Int).SetBytes(qBytes[1 : xLength+1])
	y := new(big.Int).SetBytes(qBytes[xLength+1:])

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

	curveOrder := curve.Params().N
	if priv.Cmp(curveOrder) >= 0 {
		return nil, fmt.Errorf("invalid elliptic curve private key value")
	}

	// validate X and Y values
	pKey := make([]byte, (curveOrder.BitLen()+7)/8)
	copy(pKey[len(pKey)-len(priv.Bytes()):], priv.Bytes())
	xC, yC := curve.ScalarBaseMult(pKey)
	if x.Cmp(xC) != 0 {
		return nil, fmt.Errorf("calculated X doesn't correspond to public one")
	}
	if y.Cmp(yC) != 0 {
		return nil, fmt.Errorf("calculated Y doesn't correspond to public one")
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
