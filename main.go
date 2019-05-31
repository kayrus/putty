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
	"io/ioutil"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"
)

const MaxKeyBlobSize = 262144
const MaxKeyBlobLines = (MaxKeyBlobSize / 48)

type Key struct {
	Algo        string
	PublicKey   []byte
	PrivateKey  []byte
	Comment     string
	Encryption  string
	PrivateMac  string
	PrivateHash string
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

// LoadFromFile reads PuTTY key and loads its contents into the struct
func (k *Key) LoadFromFile(path string) error {
	path = filepath.FromSlash(path)

	b, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	return k.Load(b)
}

// Load loads PuTTY key bytes into the struct
func (k *Key) Load(b []byte) error {
	r := bytes.NewReader(b)

	v, err := decodeFields(bufio.NewReader(r))
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
		return nil, fmt.Errorf("Expect password")
	}

	err := k.decrypt(password)
	if err != nil {
		return nil, err
	}

	switch k.Algo {
	case "ssh-rsa":
		return k.readRSA(password)
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return k.readECDSA(password)
	case "ssh-dss":
		return k.readDSA(password)
	case "ssh-ed25519":
		return k.readED25519(password)
	}

	return nil, fmt.Errorf("unsupported key type %q", k.Algo)
}

// golang implementation of putty C read_header
func readHeaderFormat(r *bufio.Reader) ([]byte, error) {
	var buf []byte

	for {
		c, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if c == '\n' || c == '\r' {
			return nil, fmt.Errorf("Unexpected newlines") /* failure */
		}
		if c == ':' {
			c, err = r.ReadByte()
			if err != nil {
				return nil, err
			}
			if c != ' ' {
				return nil, fmt.Errorf(`Expected whitespace, got "0x%02X"`, c)
			}
			break
		}
		buf = append(buf, c)
	}
	return buf, nil
}

// golang implementation of putty C read_body
func readBody(r *bufio.Reader) ([]byte, error) {
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

	return buf, nil
}

// golang implementation of putty C read_blob
func readBlob(r *bufio.Reader, nlines int) ([]byte, error) {
	var buf []byte

	for i := 0; i < nlines; i++ {
		line, err := readBody(r)
		if err != nil {
			return nil, err
		}
		linelen := len(line)
		if linelen%4 != 0 || linelen > 64 {
			return nil, fmt.Errorf("Invalid blob string length")
		}
		buf = append(buf, line...)
	}

	return buf, nil
}

// Decode fields in the order defined by "fieldsOrder"
func decodeFields(r *bufio.Reader) (*Key, error) {
	var oldFmt bool

	k := new(Key)

	for i, h := range fieldsOrder {
		if i == 5 && !oldFmt {
			// new format, detecting "PrivateMac" instead of "PrivateHash"
			continue
		}

		header, err := readHeaderFormat(r)
		if err != nil {
			if i == 0 {
				return nil, fmt.Errorf("No header line found in key file")
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
					return nil, fmt.Errorf("PuTTY key format too old")
				case fmt.Sprintf("%s%d", h, 2):
					oldFmt = false
				default:
					return nil, fmt.Errorf("PuTTY key format too new")
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
					return nil, fmt.Errorf("Invalid key algorithm: %s", b)
				}
				k.Algo = string(b)
			case 1:
				// check the encryption format
				switch string(b) {
				case "none":
				case "aes256-cbc":
				default:
					return nil, fmt.Errorf("Invalid encryption format: %s", b)
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
				if n >= MaxKeyBlobLines {
					return nil, fmt.Errorf("Invalid number of lines: %d", n)
				}
				bs, err := readBlob(r, n)
				if err != nil {
					return nil, fmt.Errorf(`Failed to read blob data for %q: %s`, v, err)
				}

				v, err := base64.StdEncoding.DecodeString(string(bs))
				if err != nil {
					return nil, fmt.Errorf("base64 decode error for the %s header", h)
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
				return nil, fmt.Errorf("Index is out of range")
			}
		} else {
			if i == 0 {
				return nil, fmt.Errorf("Not a PuTTY SSH-2 private key")
			}
			return nil, fmt.Errorf(`Unexpected header %q, expecting %q`, v, h)
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

	var block cipher.Block
	var err error
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
	if block, err = aes.NewCipher(k[:32]); err != nil {
		return nil, err
	}

	// zero IV
	cbc := cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize))

	// decrypt
	cbc.CryptBlocks(ciphertext, ciphertext)

	return ciphertext, nil
}

// ValidateHMAC validates PuTTY key HMAC
func (k Key) ValidateHMAC(password []byte) error {
	payload := bytes.NewBuffer(nil)
	binary.Write(payload, binary.BigEndian, uint32(len(k.Algo)))
	payload.WriteString(k.Algo)
	binary.Write(payload, binary.BigEndian, uint32(len(k.Encryption)))
	payload.WriteString(k.Encryption)
	binary.Write(payload, binary.BigEndian, uint32(len(k.Comment)))
	payload.WriteString(k.Comment)
	binary.Write(payload, binary.BigEndian, uint32(len(k.PublicKey)))
	payload.Write(k.PublicKey)
	binary.Write(payload, binary.BigEndian, uint32(len(k.PrivateKey)))
	payload.Write(k.PrivateKey)

	sha1sum := sha1.New()
	sha1sum.Write([]byte("putty-private-key-file-mac-key"))
	if len(password) > 0 {
		sha1sum.Write(password)
	}

	hmacsha1 := hmac.New(sha1.New, sha1sum.Sum(nil))
	hmacsha1.Write(payload.Bytes())

	mac := hex.EncodeToString(hmacsha1.Sum(nil))
	if mac != k.PrivateMac {
		return fmt.Errorf("Calculated MAC %q doesn't correspond to %q", mac, k.PrivateMac)
	}

	return nil
}

func readBytes(src []byte, offset *uint32) ([]byte, error) {
	var l uint32
	uint32size := uint32(4)
	sl := uint32(len(src))

	if *offset+uint32size > sl {
		return nil, fmt.Errorf("cannot detect element size: %d index out of range %d", *offset+l, sl)
	}

	err := binary.Read(bytes.NewBuffer(src[*offset:*offset+uint32size]), binary.BigEndian, &l)
	if err != nil {
		return nil, err
	}

	*offset += uint32size

	if *offset+l > sl {
		return nil, fmt.Errorf("cannot read element: %d index out of range %d", *offset+l, sl)
	}

	*offset += l

	return src[*offset-l : *offset], nil
}

func readString(src []byte, offset *uint32) (string, error) {
	b, err := readBytes(src, offset)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func readBigInt(src []byte, offset *uint32) (*big.Int, error) {
	b, err := readBytes(src, offset)
	if err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(b), nil
}

func (k *Key) decrypt(password []byte) (err error) {
	// decrypt the key, when it is encrypted
	if k.Encryption != "none" {
		v, err := decryptCBC(password, k.PrivateKey)
		if err != nil {
			return err
		}
		k.PrivateKey = v
	}

	// validate key signature
	err = k.ValidateHMAC(password)
	if err != nil {
		return err
	}

	return nil
}

func (k Key) checkGarbage(offset uint32) error {
	if k.Encryption != "none" {
		// normalize the size of the decrypted part (should be % aes.BlockSize)
		offset = offset + aes.BlockSize - offset&(aes.BlockSize-1)
	}

	// check private block size
	if len(k.PrivateKey) != int(offset) {
		return fmt.Errorf("Wrong private key size: got %d, expected %d", len(k.PrivateKey), offset)
	}

	return nil
}
