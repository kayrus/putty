package putty

import (
	"crypto/dsa"
	"fmt"
	"math/big"
)

func (k Key) readDSA() (*dsa.PrivateKey, error) {
	var pub struct {
		Header string
		P      *big.Int
		Q      *big.Int
		G      *big.Int
		Pub    *big.Int
	}
	err := unmarshal(k.PublicKey, &pub, false)
	if err != nil {
		return nil, err
	}

	if pub.Header != k.Algo {
		return nil, fmt.Errorf("invalid header inside public key: %q: expected %q", pub.Header, k.Algo)
	}

	var priv *big.Int
	err = unmarshal(k.PrivateKey, &priv, k.Encryption != "none")
	if err != nil {
		return nil, err
	}

	privateKey := &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: pub.P,
				Q: pub.Q,
				G: pub.G,
			},
			Y: pub.Pub,
		},
		X: priv,
	}

	return privateKey, nil
}
