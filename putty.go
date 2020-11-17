package putty

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// const from putty
const maxKeyBlobSize = 262144
const maxKeyBlobLines = (maxKeyBlobSize / 48)

// max header length from putty read_header
const maxHeaderLength = 39

type Key struct {
	Algo        string
	PublicKey   []byte
	PrivateKey  []byte
	Comment     string
	Encryption  string
	PrivateMac  string
	PrivateHash string
	decrypted   bool
}

var fieldsOrder = []string{
	"PuTTY-User-Key-File-",
	"Encryption",
	"Comment",
	"Public-Lines",
	"Private-Lines",
	"Private-Hash",
	"Private-MAC",
}

type reader interface {
	Read([]byte) (int, error)
	ReadByte() (byte, error)
	UnreadByte() error
}

// LoadFromFile reads PuTTY key and loads its contents into the struct
func (k *Key) LoadFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	v, err := decodeFields(bufio.NewReader(f))
	if err != nil {
		return err
	}

	*k = *v

	return nil
}

// Load loads PuTTY key bytes into the struct
func (k *Key) Load(b []byte) error {
	v, err := decodeFields(bytes.NewReader(b))
	if err != nil {
		return err
	}

	*k = *v

	return nil
}

// NewFromFile creates new PuTTY structure from file
func NewFromFile(path string) (*Key, error) {
	k := new(Key)

	err := k.LoadFromFile(path)
	if err != nil {
		return nil, err
	}

	return k, nil
}

// New creates new PuTTY structure from key bytes
func New(b []byte) (*Key, error) {
	k := new(Key)

	err := k.Load(b)
	if err != nil {
		return nil, err
	}

	return k, nil
}

// ParseRawPrivateKey returns a private key from a PuTTY encoded private key. It
// supports RSA (PKCS#1), DSA (OpenSSL), ECDSA and ED25519 private keys.
func (k *Key) ParseRawPrivateKey(password []byte) (interface{}, error) {
	if k.Encryption != "none" && len(password) == 0 {
		return nil, fmt.Errorf("expecting password")
	}

	err := k.decrypt(password)
	if err != nil {
		return nil, err
	}

	switch k.Algo {
	case "ssh-rsa":
		return k.readRSAPrivateKey()
	case "ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521":
		return k.readECDSAPrivateKey()
	case "ssh-dss":
		return k.readDSAPrivateKey()
	case "ssh-ed25519":
		return k.readED25519PrivateKey()
	}

	return nil, fmt.Errorf("unsupported key type %q", k.Algo)
}

// ParseRawPublicKey returns a public key from a PuTTY encoded private key. It
// supports the same key types as ParseRawPrivateKey, and will work even if the private part is encrypted
func (k *Key) ParseRawPublicKey() (interface{}, error) {
	switch k.Algo {
	case "ssh-rsa":
		return k.readRSAPublicKey()
	case "ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521":
		return k.readECDSAPublicKey()
	case "ssh-dss":
		return k.readDSAPublicKey()
	case "ssh-ed25519":
		return k.readED25519PublicKey()
	}

	return nil, fmt.Errorf("unsupported key type %q", k.Algo)
}

// golang implementation of putty C read_header
func readHeader(r reader) ([]byte, error) {
	var length = maxHeaderLength
	var buf []byte

	for {
		c, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if c == '\n' || c == '\r' {
			return nil, fmt.Errorf("unexpected newlines") /* failure */
		}
		if c == ':' {
			c, err = r.ReadByte()
			if err != nil {
				return nil, err
			}
			if c != ' ' {
				return nil, fmt.Errorf(`expected whitespace, got "0x%02X"`, c)
			}
			return buf, nil /* success! */
		}
		if length == 0 {
			break /* failure */
		}
		buf = append(buf, c)
		length--
	}

	return nil, fmt.Errorf("header length exceeded %d bytes", maxHeaderLength) /* failure */
}

// golang implementation of putty C read_body
func readBody(r reader) ([]byte, error) {
	var buf []byte

	for {
		c, err := r.ReadByte()
		if err != nil && err != io.EOF {
			return nil, err
		}
		if c == '\r' || c == '\n' || err == io.EOF {
			if err == nil {
				c, err = r.ReadByte()
				if err == io.EOF {
					return buf, nil
				}
				if err != nil {
					return nil, err
				}
				if c != '\r' && c != '\n' {
					if err := r.UnreadByte(); err != nil {
						return nil, err
					}
				}
			}
			return buf, nil
		}
		buf = append(buf, c)
	}
}

// golang implementation of putty C read_blob
func readBlob(r reader, nlines int) ([]byte, error) {
	var buf []byte

	for i := 0; i < nlines; i++ {
		line, err := readBody(r)
		if err != nil {
			return nil, err
		}
		linelen := len(line)
		if linelen%4 != 0 || linelen > 64 {
			return nil, fmt.Errorf("invalid blob string length")
		}
		buf = append(buf, line...)
	}

	return buf, nil
}

// Decode fields in the order defined by "fieldsOrder"
func decodeFields(r reader) (*Key, error) {
	var oldFmt bool

	k := new(Key)

	for i, h := range fieldsOrder {
		if i == 5 && !oldFmt {
			// new format, detecting "PrivateMac" instead of "PrivateHash"
			continue
		}

		header, err := readHeader(r)
		if err != nil {
			if i == 0 {
				return nil, fmt.Errorf("no header line found in key file: %s", err)
			}
			return nil, err
		}

		v := string(header)
		if (i == 0 && strings.HasPrefix(v, h)) || v == h {
			// check the header
			if i == 0 {
				switch v {
				case fmt.Sprintf("%s%d", h, 1):
					oldFmt = true
					return nil, fmt.Errorf("PuTTY key format is too old")
				case fmt.Sprintf("%s%d", h, 2):
					oldFmt = false
				default:
					return nil, fmt.Errorf("PuTTY key format is too new")
				}
			}

			b, err := readBody(r)
			if err != nil {
				return nil, err
			}

			switch i {
			case 0:
				// check the key algo
				switch string(b) {
				case "ssh-rsa":
				case "ssh-dss":
				case "ecdsa-sha2-nistp256":
				case "ecdsa-sha2-nistp384":
				case "ecdsa-sha2-nistp521":
				case "ssh-ed25519":
				default:
					return nil, fmt.Errorf("invalid key algorithm: %s", b)
				}
				k.Algo = string(b)
			case 1:
				// check the encryption format
				switch string(b) {
				case "none":
				case "aes256-cbc":
				default:
					return nil, fmt.Errorf("invalid encryption format: %s", b)
				}

				k.Encryption = string(b)
			case 2:
				k.Comment = string(b)
			case 3, 4:
				// Read blobs data
				n, err := strconv.Atoi(string(b))
				if err != nil {
					return nil, err
				}
				if n >= maxKeyBlobLines {
					return nil, fmt.Errorf("invalid number of lines: %d", n)
				}
				bs, err := readBlob(r, n)
				if err != nil {
					return nil, fmt.Errorf("failed to read blob data for %q: %s", v, err)
				}

				v, err := base64.StdEncoding.DecodeString(string(bs))
				if err != nil {
					return nil, fmt.Errorf("%q header decode error: %s", h, err)
				}
				if i == 3 {
					k.PublicKey = v
				} else {
					k.PrivateKey = v
				}
			case 5:
				// read hash
				k.PrivateHash = string(b)
			case 6:
				// read signature
				k.PrivateMac = string(b)
			default:
				return nil, fmt.Errorf("index is out of range")
			}
		} else {
			if i == 0 {
				return nil, fmt.Errorf("not a PuTTY SSH-2 private key")
			}
			return nil, fmt.Errorf("unexpected header %q, expecting %q", v, h)
		}
	}

	return k, nil
}

func decryptCBC(password, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	var seq int
	var k []byte

	// calculate and combine sha1 sums of each seq+password, then truncate them to a 32 bytes (256 bit CBC) key
	for {
		t := []byte{0, 0, 0, byte(seq)}
		t = append(t, password...)
		h := sha1.Sum(t)
		k = append(k, h[:]...)
		if len(k) >= 32 {
			break
		}
		seq++
	}

	// initialize AES 256 bit cipher
	block, err := aes.NewCipher(k[:32])
	if err != nil {
		return nil, err
	}

	// zero IV
	iv := make([]byte, aes.BlockSize)
	cbc := cipher.NewCBCDecrypter(block, iv)

	// decrypt
	cbc.CryptBlocks(ciphertext, ciphertext)

	return ciphertext, nil
}

// validateHMAC validates PuTTY key HMAC
func (k Key) validateHMAC(password []byte) error {
	sha1sum := sha1.New()
	sha1sum.Write([]byte("putty-private-key-file-mac-key"))
	if len(password) > 0 {
		sha1sum.Write(password)
	}

	hmacsha1 := hmac.New(sha1.New, sha1sum.Sum(nil))

	binary.Write(hmacsha1, binary.BigEndian, uint32(len(k.Algo)))
	hmacsha1.Write([]byte(k.Algo))
	binary.Write(hmacsha1, binary.BigEndian, uint32(len(k.Encryption)))
	hmacsha1.Write([]byte(k.Encryption))
	binary.Write(hmacsha1, binary.BigEndian, uint32(len(k.Comment)))
	hmacsha1.Write([]byte(k.Comment))
	binary.Write(hmacsha1, binary.BigEndian, uint32(len(k.PublicKey)))
	hmacsha1.Write(k.PublicKey)
	binary.Write(hmacsha1, binary.BigEndian, uint32(len(k.PrivateKey)))
	hmacsha1.Write(k.PrivateKey)

	mac := hex.EncodeToString(hmacsha1.Sum(nil))
	if mac != k.PrivateMac {
		return fmt.Errorf("calculated HMAC %q doesn't correspond to %q", mac, k.PrivateMac)
	}

	return nil
}

// decrypt decrypts the key, when it is encrypted. and validates its signature
func (k *Key) decrypt(password []byte) (err error) {
	// decrypt the key, when it is encrypted
	if !k.decrypted && k.Encryption != "none" {
		v, err := decryptCBC(password, k.PrivateKey)
		if err != nil {
			return err
		}

		k.PrivateKey = v
	}

	k.decrypted = true

	// validate key signature
	err = k.validateHMAC(password)
	if err != nil {
		return err
	}

	return nil
}
