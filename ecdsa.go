package putty

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"strings"
)

func (k Key) readECDSAPublicKey() (*ecdsa.PublicKey, error) {
	var pub struct {
		Header string
		Length string
		Bytes  []byte
	}
	_, err := unmarshal(k.PublicKey, &pub, false)
	if err != nil {
		return nil, err
	}

	if pub.Header != k.Algo {
		return nil, fmt.Errorf("invalid header inside public key: %q: expected %q", pub.Header, k.Algo)
	}

	if !strings.HasSuffix(k.Algo, pub.Length) {
		return nil, fmt.Errorf("elliptic curves %q key length doesn't correspond to %q", pub.Length, k.Algo)
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

	publicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return publicKey, nil
}

func (k *Key) setECDSAPublicKey(pk *ecdsa.PublicKey) (err error) {
	var pub struct {
		Header string
		Length string
		Bytes  []byte
	}

	switch c := pk.Curve.Params().Name; c {
	case "P-256":
		pub.Length = "nistp256"
	case "P-384":
		pub.Length = "nistp384"
	case "P-521":
		pub.Length = "nistp521"
	default:
		return fmt.Errorf("unsupported elliptic curve %s", c)
	}

	pub.Header = "ecdsa-sha2-" + pub.Length
	k.Algo = pub.Header

	x := (pk.X).Bytes()
	y := (pk.Y).Bytes()

	// balance the integers slices
	if diff := len(x) - len(y); diff > 0 {
		y = append(make([]byte, diff), y...)
	} else if diff < 0 {
		x = append(make([]byte, -diff), x...)
	}

	pub.Bytes = append([]byte{4}, x...)
	pub.Bytes = append(pub.Bytes, y...)

	k.PublicKey, err = marshal(&pub)
	return
}

func (k *Key) readECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	publicKey, err := k.readECDSAPublicKey()
	if err != nil {
		return nil, err
	}

	var priv *big.Int
	k.keySize, err = unmarshal(k.PrivateKey, &priv, k.padded)
	if err != nil {
		return nil, err
	}

	curveOrder := publicKey.Curve.Params().N
	if priv.Cmp(curveOrder) >= 0 {
		return nil, fmt.Errorf("invalid elliptic curve private key value")
	}

	// validate X and Y values
	pKey := make([]byte, (curveOrder.BitLen()+7)/8)
	copy(pKey[len(pKey)-len(priv.Bytes()):], priv.Bytes())
	xC, yC := publicKey.Curve.ScalarBaseMult(pKey)
	if publicKey.X.Cmp(xC) != 0 {
		return nil, fmt.Errorf("calculated X doesn't correspond to public one")
	}
	if publicKey.Y.Cmp(yC) != 0 {
		return nil, fmt.Errorf("calculated Y doesn't correspond to public one")
	}

	privateKey := &ecdsa.PrivateKey{
		D:         priv,
		PublicKey: *publicKey,
	}

	return privateKey, nil
}

func (k *Key) setECDSAPrivateKey(pk *ecdsa.PrivateKey) (err error) {
	err = k.setECDSAPublicKey(&pk.PublicKey)
	if err != nil {
		return
	}
	k.PrivateKey, err = marshal(&pk.D)
	k.keySize = len(k.PrivateKey)
	k.padded = false
	return
}
