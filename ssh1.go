package putty

import (
	"bytes"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/pschou/go-cbc3"
)

var (
	type_SSH1_CIPHER_DES3_CBC3 = byte(3)
)

func (k *Key) MarshalSSH1WithPassword(password string) ([]byte, error) {
	return k.saveSSH1([]byte(password), rand.Reader)
}
func (k *Key) MarshalSSH1() ([]byte, error) {
	return k.saveSSH1(nil, rand.Reader)
}

func (k *Key) saveSSH1(password []byte, rand io.Reader) ([]byte, error) {
	if len(k.PrivateKey) == 0 {
		// If we don't have a private key, just return the public key
		pub, err := k.readRSAPublicKey()
		if err != nil {
			return nil, err
		}
		return []byte(fmt.Sprintf("%d %d %s %s\r\n",
			pub.N.BitLen(), pub.E, pub.N, k.Comment)), nil
	}

	// Parse the private and public keys
	priv, err := k.readRSAPrivateKey()
	if err != nil {
		return nil, err
	}

	// Write to buffer then return the contents
	var pubBytes, privBytes bytes.Buffer
	pubBytes.Write([]byte("SSH PRIVATE KEY FILE FORMAT 1.1\n\x00"))
	if password == nil {
		pubBytes.Write([]byte{0})
	} else {
		pubBytes.Write([]byte{type_SSH1_CIPHER_DES3_CBC3})
	}
	pubBytes.Write(make([]byte, 4))
	writeInt32(&pubBytes, uint32(priv.PublicKey.N.BitLen()))
	writeBigInt1(&pubBytes, priv.PublicKey.N)
	writeBigInt1(&pubBytes, big.NewInt(int64(priv.PublicKey.E)))
	writeString2(&pubBytes, k.Comment)

	ab := make([]byte, 2)
	rand.Read(ab)
	privBytes.Write(ab)
	privBytes.Write(ab)

	writeBigInt1(&privBytes, priv.D)
	writeBigInt1(&privBytes, priv.Precomputed.Qinv)
	writeBigInt1(&privBytes, priv.Primes[1])
	writeBigInt1(&privBytes, priv.Primes[0])

	privB := privBytes.Bytes()
	if len(privB)%8 > 0 {
		privB = append(privB, make([]byte, 8-len(privB)%8)...)
	}
	if password != nil {
		// Decrypt the private porition of the key
		hash := md5.Sum(password)
		key := hash[:]
		c1, err := des.NewCipher(key[:8])
		if err != nil {
			return nil, fmt.Errorf("Unable to build DES block 1, %s", err)
		}
		c2, err := des.NewCipher(key[8:])
		if err != nil {
			return nil, fmt.Errorf("Unable to build DES block 2, %s", err)
		}
		c3, err := des.NewCipher(key[:8])
		if err != nil {
			return nil, fmt.Errorf("Unable to build DES block 3, %s", err)
		}
		crypter := cbc3.NewEncrypter(c1, c2, c3, make([]byte, 24))
		crypter.CryptBlocks(privB, privB)
	}

	//if !strings.HasPrefix(string(b), "SSH PRIVATE KEY FILE FORMAT 1.1\n") {
	return append(pubBytes.Bytes(), privB...), nil
}

func (k *Key) LoadSSH1WithPassword(b []byte, password string) error {
	if !strings.HasPrefix(string(b), "SSH PRIVATE KEY FILE FORMAT 1.1\n") {
		return fmt.Errorf("Expected: SSH PRIVATE KEY FILE FORMAT 1.1")
	}
	return k.loadSSH1(b, []byte(password))
}
func (k *Key) LoadSSH1(b []byte) error {
	if strings.HasPrefix(string(b), "SSH PRIVATE KEY FILE FORMAT 1.1\n") {
		// If this file is a private key file
		return k.loadSSH1(b, nil)
	} else if parts := strings.SplitN(string(b), " ", 4); len(parts) == 4 {
		// If this file is a public key file
		e, _ := new(big.Int).SetString(parts[1], 10)
		if e == nil {
			return fmt.Errorf("Unable to read SSH1 exponent")
		}
		m, _ := new(big.Int).SetString(parts[2], 10)
		if m == nil {
			return fmt.Errorf("Unable to read SSH1 modulus")
		}
		k.Comment = strings.TrimSuffix(parts[3], "\r\n")

		return k.setRSAPublicKey(&rsa.PublicKey{
			N: m,
			E: int(e.Int64()),
		})
	}
	return fmt.Errorf("Unknown SSH1 key file format")
}

func (k *Key) loadSSH1(b, password []byte) error {
	var encrypted bool
	switch b[33] {
	case 0:
		if password != nil {
			return fmt.Errorf("Password provided, but encryption flag is not set")
		}
	case type_SSH1_CIPHER_DES3_CBC3:
		if password == nil {
			return fmt.Errorf("Password not provided, but encryption flag is set")
		}
		encrypted = true
	default:
		return fmt.Errorf("Unsupported encryption %d", b[33])
	}

	src := bytes.NewReader(b[34:])
	{
		zero, err := readInt32(src)
		if err != nil {
			return fmt.Errorf("Unable to read 4 byte padding, %s", err)
		}
		if zero != 0 {
			return fmt.Errorf("Expected zero padding, got %d", zero)
		}
	}
	bits, err := readInt32(src)
	if err != nil {
		return fmt.Errorf("Err reading the number of key bits (got %q), %s", bits, err)
	}

	// This reader only expects the MODULUS to be first
	var e, m *big.Int
	m, err = readBigInt1(src)
	if err != nil {
		return fmt.Errorf("Unable to read SSH1 modulus, %s", err)
	}
	e, err = readBigInt1(src)
	if err != nil {
		return fmt.Errorf("Unable to read SSH1 exponent, %s", err)
	}

	k.Comment, err = readString2(src)
	if err != nil {
		return fmt.Errorf("Unable to read SSH1 comment, %s", err)
	}

	if encrypted {
		// Decrypt the private porition of the key
		hash := md5.Sum(password)
		key := hash[:]
		c1, err := des.NewCipher(key[:8])
		if err != nil {
			return fmt.Errorf("Unable to build DES block 1, %s", err)
		}
		c2, err := des.NewCipher(key[8:])
		if err != nil {
			return fmt.Errorf("Unable to build DES block 2, %s", err)
		}
		c3, err := des.NewCipher(key[:8])
		if err != nil {
			return fmt.Errorf("Unable to build DES block 3, %s", err)
		}
		pos := len(b) - src.Len()
		crypter := cbc3.NewDecrypter(c1, c2, c3, make([]byte, 24))
		crypter.CryptBlocks(b[pos:], b[pos:])

		src = bytes.NewReader(b[pos:])
	}

	// Check the first 4 bytes for the pattern
	{
		ab := make([]byte, 4)
		src.Read(ab)

		if ab[0] != ab[2] || ab[1] != ab[3] {
			return fmt.Errorf("Expected [a] [b] [a] [b] values, wrong passphrase?")
		}
	}

	// Read in the private porition of the key
	var private_exponent, iqmp, p, q *big.Int
	private_exponent, err = readBigInt1(src)
	if err != nil {
		return fmt.Errorf("Unable to read SSH1 Private Exponent, %s", err)
	}

	iqmp, err = readBigInt1(src)
	if err != nil {
		return fmt.Errorf("Unable to read SSH1 Qinv, %s", err)
	}
	q, err = readBigInt1(src)
	if err != nil {
		return fmt.Errorf("Unable to read SSH1 Q, %s", err)
	}
	p, err = readBigInt1(src)
	if err != nil {
		return fmt.Errorf("Unable to read SSH1 P, %s", err)
	}

	/*
	 * Verify that the public data in an RSA key matches the private
	 * data. We also check the private data itself: we ensure that p >
	 * q and that iqmp really is the inverse of q mod p.
	 */

	priv := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: m,
			E: int(e.Int64()),
		},
		D:      private_exponent,
		Primes: []*big.Int{p, q},
		Precomputed: rsa.PrecomputedValues{
			Qinv: iqmp,
		},
	}

	if err := priv.Validate(); err != nil {
		return fmt.Errorf("Validation of key failed: %s", err)
	}

	return k.setRSAPrivateKey(&priv)
}

func des_xor(a, b []byte) {
	for i := range a {
		a[i] ^= b[i]
	}
}
