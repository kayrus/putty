package putty

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"strings"
)

func (k Key) readECDSA() (*ecdsa.PrivateKey, error) {
	var pub struct {
		Header string
		Length string
		Bytes  []byte
	}
	err := unmarshal(k.PublicKey, &pub, false)
	if err != nil {
		return nil, err
	}

	if pub.Header != k.Algo {
		return nil, fmt.Errorf("invalid header inside public key: %q: expected %q", pub.Header, k.Algo)
	}

	if !strings.HasSuffix(k.Algo, pub.Length) {
		return nil, fmt.Errorf("elliptic curves %q key length doesn't correspond to %q", pub.Length, k.Algo)
	}

	var priv *big.Int
	err = unmarshal(k.PrivateKey, &priv, k.Encryption != "none")
	if err != nil {
		return nil, err
	}

	length := len(pub.Bytes) / 2
	x := new(big.Int).SetBytes(pub.Bytes[1 : length+1])
	y := new(big.Int).SetBytes(pub.Bytes[length+1:])

	var curve elliptic.Curve
	switch pub.Length {
	case "nistp256":
		curve = elliptic.P256()
	case "nistp384":
		curve = elliptic.P384()
	case "nistp521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported elliptic curves key length %q", pub.Length)
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
