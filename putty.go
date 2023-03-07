package putty

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// const from putty
	maxKeyBlobSize  = 262144
	maxKeyBlobLines = (maxKeyBlobSize / 48)

	// max header length from putty read_header
	maxHeaderLength = 39
	puttyHeaderV1   = "PuTTY-User-Key-File-1"
	puttyHeaderV2   = "PuTTY-User-Key-File-2"
	puttyHeaderV3   = "PuTTY-User-Key-File-3"

	// cipher lengths
	cipherKeyLength = 32
	cipherIVLength  = 16
	macKeyLength    = 32

	// argon2 key length
	argon2KeyLength = cipherKeyLength + cipherIVLength + macKeyLength
)

type Key struct {
	Version           int
	Algo              string
	PublicKey         []byte
	PrivateKey        []byte
	KeyDerivation     string
	Argon2Memory      uint32
	Argon2Passes      uint32
	Argon2Parallelism uint8
	Argon2Salt        []byte
	Comment           string
	Encryption        string
	PrivateMac        []byte
	padded            bool
	keySize           int
}

func (k Key) Clone() *Key {
	return &Key{
		Version:           k.Version,
		Algo:              k.Algo,
		PublicKey:         append([]byte{}, k.PublicKey...),
		PrivateKey:        append([]byte{}, k.PrivateKey...),
		KeyDerivation:     k.KeyDerivation,
		Argon2Memory:      k.Argon2Memory,
		Argon2Passes:      k.Argon2Passes,
		Argon2Parallelism: k.Argon2Parallelism,
		Argon2Salt:        append([]byte{}, k.Argon2Salt...),
		Comment:           k.Comment,
		Encryption:        k.Encryption,
		PrivateMac:        append([]byte{}, k.PrivateMac...),
		padded:            k.padded,
		keySize:           k.keySize,
	}
}

var noNewLines = strings.NewReplacer("\r", "", "\n", "")

// Marshal returns the key in the raw ppk format for saving to a file.
func (k *Key) Marshal() (ret []byte, err error) {
	// Helpful notes about the putty formats:
	// https://tartarus.org/~simon/putty-snapshots/htmldoc/AppendixC.html
	buf := new(bytes.Buffer)
	switch k.Version {
	case 1:
		buf.WriteString(puttyHeaderV1)
	case 2:
		buf.WriteString(puttyHeaderV2)
	case 3, 0:
		k.Version = 3
		buf.WriteString(puttyHeaderV3)
	default:
		return ret, fmt.Errorf("PuTTY key format verion needs to be set to 1, 2, or 3")
	}

	switch k.Algo {
	case "ssh-rsa",
		"ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521",
		"ssh-dss",
		"ssh-ed25519":
		fmt.Fprintf(buf, ": %s\r\n", k.Algo)
	default:
		return ret, fmt.Errorf("invalid algorithm")
	}

	fmt.Fprintf(buf, "Encryption: %s\r\n", k.Encryption)

	if k.Comment == "" {
		k.Comment = "PuTTY key"
	}
	fmt.Fprintf(buf, "Comment: %s\r\n", noNewLines.Replace(k.Comment))

	pub := splitByWidth(base64.StdEncoding.EncodeToString(k.PublicKey), 64)
	fmt.Fprintf(buf, "Public-Lines: %d\r\n", len(pub))
	fmt.Fprintf(buf, "%s\r\n", strings.Join(pub, "\r\n"))

	if len(k.PrivateKey) > 0 {
		if k.KeyDerivation != "" {
			fmt.Fprintf(buf, "Key-Derivation: %s\r\n", k.KeyDerivation)
		}
		if k.Argon2Memory > 0 {
			fmt.Fprintf(buf, "Argon2-Memory: %d\r\n", k.Argon2Memory)
		}
		if k.Argon2Passes > 0 {
			fmt.Fprintf(buf, "Argon2-Passes: %d\r\n", k.Argon2Passes)
		}
		if k.Argon2Parallelism > 0 {
			fmt.Fprintf(buf, "Argon2-Parallelism: %d\r\n", k.Argon2Parallelism)
		}
		if len(k.Argon2Salt) > 0 {
			fmt.Fprintf(buf, "Argon2-Salt: %02x\r\n", k.Argon2Salt)
		}

		priv := splitByWidth(base64.StdEncoding.EncodeToString(k.PrivateKey), 64)
		fmt.Fprintf(buf, "Private-Lines: %d\r\n", len(priv))
		fmt.Fprintf(buf, "%s\r\n", strings.Join(priv, "\r\n"))

		if k.Encryption == "none" {
			k.calculateHMAC(nil)
		}
		if k.Version == 1 && k.Encryption == "none" {
			fmt.Fprintf(buf, "Private-Hash: %0x", k.PrivateMac)
		} else {
			fmt.Fprintf(buf, "Private-MAC: %0x", k.PrivateMac)
		}
	}
	return buf.Bytes(), nil
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

// SetPrivateKey sets the private key.  It supports RSA (PKCS#1), DSA (OpenSSL), ECDSA and ED25519 private keys.
func (k *Key) SetKey(key interface{}) (err error) {
	switch PrivateKey := key.(type) {
	case *rsa.PrivateKey:
		err = k.setRSAPrivateKey(PrivateKey)
	case rsa.PrivateKey:
		err = k.setRSAPrivateKey(&PrivateKey)

	case *dsa.PrivateKey:
		err = k.setDSAPrivateKey(PrivateKey)
	case dsa.PrivateKey:
		err = k.setDSAPrivateKey(&PrivateKey)

	case *ecdsa.PrivateKey:
		err = k.setECDSAPrivateKey(PrivateKey)
	case ecdsa.PrivateKey:
		err = k.setECDSAPrivateKey(&PrivateKey)

	case *ed25519.PrivateKey:
		err = k.setED25519PrivateKey(PrivateKey)
	case ed25519.PrivateKey:
		err = k.setED25519PrivateKey(&PrivateKey)
	default:
		return fmt.Errorf("Unknown key type: %T", key)
	}
	if err == nil {
		k.Encryption = "none"
	}
	return
}

// ParseRawPrivateKey returns a private key from a PuTTY encoded private key. It
// supports RSA (PKCS#1), DSA (OpenSSL), ECDSA and ED25519 private keys.
func (k *Key) ParseRawPrivateKey(password []byte) (ret interface{}, err error) {
	if k.Encryption != "none" && len(password) == 0 {
		return nil, fmt.Errorf("expecting password")
	}

	// Fall back if an error happens
	priv := append([]byte{}, k.PrivateKey...)
	defer func() {
		if err != nil {
			k.PrivateKey = priv
		} else {
			if k.Version == 3 {
				k.KeyDerivation = ""
				k.Argon2Memory = 0
				k.Argon2Passes = 0
				k.Argon2Parallelism = 0
				k.Argon2Salt = []byte{}
			}
			k.Encryption = "none"
			if k.keySize == 0 {
				k.keySize = len(k.PrivateKey)
			} else {
				k.PrivateKey = k.PrivateKey[:k.keySize]
			}
			k.calculateHMAC(nil)
		}
	}()

	err = k.decrypt(password)
	if err != nil {
		return
	}

	switch k.Algo {
	case "ssh-rsa":
		ret, err = k.readRSAPrivateKey()
	case "ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521":
		ret, err = k.readECDSAPrivateKey()
	case "ssh-dss":
		ret, err = k.readDSAPrivateKey()
	case "ssh-ed25519":
		ret, err = k.readED25519PrivateKey()
	default:
		return nil, fmt.Errorf("unsupported key type %q", k.Algo)
	}
	return
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

// Decode fields
func decodeFields(r reader) (*Key, error) {
	k := new(Key)

	for {
		header, err := readHeader(r)
		if err != nil {
			if err == io.EOF {
				// finish the loop
				break
			}
			return nil, fmt.Errorf("failed to read header: %v", err)
		}

		h := string(header)
		b, err := readBody(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read %q data: %v", h, err)
		}

		switch h {
		case puttyHeaderV1,
			puttyHeaderV2,
			puttyHeaderV3:
			// check the header
			switch h {
			case puttyHeaderV1:
				k.Version = 1
			case puttyHeaderV2:
				k.Version = 2
			case puttyHeaderV3:
				k.Version = 3
			default:
				return nil, fmt.Errorf("PuTTY key format verion is too new")
			}

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
		case "Encryption":
			// check the encryption format
			switch string(b) {
			case "none":
				k.padded = false
			case "aes256-cbc":
				k.padded = true
			default:
				return nil, fmt.Errorf("invalid encryption format: %s", b)
			}

			k.Encryption = string(b)
		case "Comment":
			k.Comment = string(b)
		case "Public-Lines",
			"Private-Lines":
			// Read blobs data
			n, err := strconv.Atoi(string(b))
			if err != nil {
				return nil, fmt.Errorf("failed to get the %q number: %v", h, err)
			}
			if n >= maxKeyBlobLines {
				return nil, fmt.Errorf("invalid number of lines: %d", n)
			}
			bs, err := readBlob(r, n)
			if err != nil {
				return nil, fmt.Errorf("failed to read blob data for %q: %s", h, err)
			}

			v, err := base64.StdEncoding.DecodeString(string(bs))
			if err != nil {
				return nil, fmt.Errorf("%q header decode error: %s", h, err)
			}

			if h == "Public-Lines" {
				k.PublicKey = v
			} else {
				k.PrivateKey = v
			}
		case "Private-Hash",
			"Private-MAC":
			// read hash or signature
			if k.Version == 0 {
				return nil, fmt.Errorf("cannot read %q without a header: %v", h, err)
			}

			k.PrivateMac, err = hex.DecodeString(string(b))
			if err != nil {
				return nil, fmt.Errorf("failed to decode the %q hex string: %v", h, err)
			}
		default:
			if k.Version < 3 {
				return nil, fmt.Errorf("%q header is unsupported in version %d", h, k.Version)
			}
			switch h {
			case "Key-Derivation":
				k.KeyDerivation = string(b)
				switch k.KeyDerivation {
				case "Argon2id", "Argon2i":
				default:
					return nil, fmt.Errorf("the %q value is not supported in %q", k.KeyDerivation, h)
				}
			case "Argon2-Memory":
				n, err := strconv.Atoi(string(b))
				if err != nil {
					return nil, fmt.Errorf("failed to get the %q number: %v", h, err)
				}
				k.Argon2Memory = uint32(n)
			case "Argon2-Passes":
				n, err := strconv.Atoi(string(b))
				if err != nil {
					return nil, fmt.Errorf("failed to get the %q number: %v", h, err)
				}
				k.Argon2Passes = uint32(n)
			case "Argon2-Parallelism":
				n, err := strconv.Atoi(string(b))
				if err != nil {
					return nil, fmt.Errorf("failed to get the %q number: %v", h, err)
				}
				k.Argon2Parallelism = uint8(n)
			case "Argon2-Salt":
				k.Argon2Salt, err = hex.DecodeString(string(b))
				if err != nil {
					return nil, fmt.Errorf("failed to decode the %q hex string: %v", h, err)
				}
			default:
				return nil, fmt.Errorf("%q header is unknown in version %d", h, k.Version)
			}
		}
	}

	if k.Version == 0 {
		return nil, fmt.Errorf("key version is unknown")
	}

	if k.Algo == "" {
		return nil, fmt.Errorf("key algo is empty")
	}

	if len(k.PrivateKey) > 0 {
		if k.Encryption == "" {
			return nil, fmt.Errorf("key encryption is empty")
		}

		if len(k.PrivateMac) == 0 {
			return nil, fmt.Errorf("key MAC is empty")
		}
	}

	if k.Version >= 3 && k.Encryption != "none" {
		if k.KeyDerivation == "" {
			return nil, fmt.Errorf("argon2 key deriviation is empty")
		}
		if k.Argon2Passes < 1 {
			return nil, fmt.Errorf("argon2 passes cannot be less than one")
		}
		if k.Argon2Parallelism < 1 {
			return nil, fmt.Errorf("argon2 parallelism cannot be less than one")
		}
		if len(k.Argon2Salt) == 0 {
			return nil, fmt.Errorf("argon2 salt is empty")
		}
	}

	return k, nil
}

func decryptCBC(cipherKey, cipherIV, macKey, ciphertext []byte) error {
	if len(ciphertext) < aes.BlockSize {
		return fmt.Errorf("ciphertext is too short")
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	// initialize AES 256 bit cipher
	cipherBlock, err := aes.NewCipher(cipherKey)
	if err != nil {
		return fmt.Errorf("failed to initialize a cipher block for decrypt: %v", err)
	}

	// decrypt
	cipher.NewCBCDecrypter(cipherBlock, cipherIV).CryptBlocks(ciphertext, ciphertext)

	return nil
}

func encryptCBC(cipherKey, cipherIV, macKey, ciphertext []byte) error {
	if len(ciphertext) < aes.BlockSize {
		return fmt.Errorf("ciphertext is too short")
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	// initialize AES 256 bit cipher
	cipherBlock, err := aes.NewCipher(cipherKey)
	if err != nil {
		return fmt.Errorf("failed to initialize a cipher block for encrypt: %v", err)
	}

	// encrypt
	cipher.NewCBCEncrypter(cipherBlock, cipherIV).CryptBlocks(ciphertext, ciphertext)

	return nil
}

// calculateHMAC calculates PuTTY key HMAC with a hash function
func (k *Key) calculateHMAC(password []byte) error {
	_, _, macKey, err := k.deriveKeys(password)
	if err != nil {
		return err
	}
	keyCut := len(k.PrivateKey)
	if k.Encryption == "none" {
		if k.keySize == 0 {
			k.keySize = len(k.PrivateKey)
		}
		keyCut = k.keySize
	}
	var hashFunc hash.Hash
	switch k.Version {
	case 1:
		if k.Encryption == "none" {
			k.PrivateMac = sha1.New().Sum(k.PrivateKey)
			return nil
		} else {
			hashFunc = hmac.New(sha1.New, addPadding(k.PrivateMac))
		}
	case 2:
		hashFunc = hmac.New(sha1.New, macKey)
	case 3:
		hashFunc = hmac.New(sha256.New, macKey)
	default:
		return fmt.Errorf("unknown key format version: %d", k.Version)
	}

	binary.Write(hashFunc, binary.BigEndian, uint32(len(k.Algo)))
	hashFunc.Write([]byte(k.Algo))
	binary.Write(hashFunc, binary.BigEndian, uint32(len(k.Encryption)))
	hashFunc.Write([]byte(k.Encryption))
	binary.Write(hashFunc, binary.BigEndian, uint32(len(k.Comment)))
	hashFunc.Write([]byte(k.Comment))
	binary.Write(hashFunc, binary.BigEndian, uint32(len(k.PublicKey)))
	hashFunc.Write(k.PublicKey)
	binary.Write(hashFunc, binary.BigEndian, uint32(len(k.PrivateKey[:keyCut])))
	hashFunc.Write(k.PrivateKey)

	k.PrivateMac = hashFunc.Sum(nil)
	return nil
}

// validateHMAC validates PuTTY key HMAC with a hash function
func (k Key) validateHMAC(hashFunc hash.Hash) error {
	binary.Write(hashFunc, binary.BigEndian, uint32(len(k.Algo)))
	hashFunc.Write([]byte(k.Algo))
	binary.Write(hashFunc, binary.BigEndian, uint32(len(k.Encryption)))
	hashFunc.Write([]byte(k.Encryption))
	binary.Write(hashFunc, binary.BigEndian, uint32(len(k.Comment)))
	hashFunc.Write([]byte(k.Comment))
	binary.Write(hashFunc, binary.BigEndian, uint32(len(k.PublicKey)))
	hashFunc.Write(k.PublicKey)
	binary.Write(hashFunc, binary.BigEndian, uint32(len(k.PrivateKey)))
	hashFunc.Write(k.PrivateKey)

	mac := hashFunc.Sum(nil)
	if !bytes.Equal(mac, k.PrivateMac) {
		return fmt.Errorf("calculated HMAC %q doesn't correspond to %q", hex.EncodeToString(mac), hex.EncodeToString(k.PrivateMac))
	}

	return nil
}

// deriveKeys returns keys to decrypt and verify the private key
func (k Key) deriveKeys(password []byte) ([]byte, []byte, []byte, error) {
	if k.Version == 2 {
		sha1sum := sha1.New()
		sha1sum.Write([]byte("putty-private-key-file-mac-key"))
		if len(password) > 0 {
			sha1sum.Write(password)
		}

		macKey := sha1sum.Sum(nil)

		var seq int
		var kb []byte

		// calculate and combine sha1 sums of each seq+password,
		// then truncate them to a 32 bytes (256 bit CBC) key
		for {
			t := []byte{0, 0, 0, byte(seq)}
			t = append(t, password...)
			h := sha1.Sum(t)
			kb = append(kb, h[:]...)
			if len(kb) >= 32 {
				break
			}
			seq++
		}

		if len(kb) < cipherKeyLength {
			return nil, nil, nil, fmt.Errorf("invalid length of the calculated cipher key")
		}

		// zero IV
		cipherIV := make([]byte, aes.BlockSize)

		return kb[:cipherKeyLength], cipherIV, macKey, nil
	}

	var h []byte
	switch k.KeyDerivation {
	case "Argon2id":
		h = argon2.IDKey(password, k.Argon2Salt, k.Argon2Passes, k.Argon2Memory, k.Argon2Parallelism, argon2KeyLength)
	case "Argon2i":
		h = argon2.Key(password, k.Argon2Salt, k.Argon2Passes, k.Argon2Memory, k.Argon2Parallelism, argon2KeyLength)
	case "":
		return nil, nil, nil, nil
	default:
		return nil, nil, nil, fmt.Errorf("%q argon2 key deriviation is not supported", k.KeyDerivation)
	}
	if len(h) != argon2KeyLength {
		return nil, nil, nil, fmt.Errorf("invalid argon2 hash length")
	}

	return h[:cipherKeyLength], // cipherKey
		h[cipherKeyLength : cipherIVLength+macKeyLength], // cipherIV
		h[cipherIVLength+macKeyLength:], // macKey
		nil
}

// Decrypt decrypts the key, when it is encrypted. and validates its signature
func (k *Key) decrypt(password []byte) (err error) {
	cipherKey, cipherIV, macKey, err := k.deriveKeys(password)
	if err != nil {
		return err
	}

	// decrypt the key, when it is encrypted
	if k.Encryption != "none" {
		err = decryptCBC(cipherKey, cipherIV, macKey, k.PrivateKey)
		if err != nil {
			return err
		}
	}

	// validate key signature
	switch k.Version {
	case 1:
		if k.Encryption == "none" {
			h := sha1.New().Sum(k.PrivateKey)
			if !bytes.Equal(h, k.PrivateMac) {
				return fmt.Errorf("calculated SHA1 sum %q doesn't correspond to %q", hex.EncodeToString(h), hex.EncodeToString(k.PrivateMac))
			}
			return nil
		} else {
			err = k.validateHMAC(hmac.New(sha1.New, addPadding(k.PrivateMac)))
		}
	case 2:
		err = k.validateHMAC(hmac.New(sha1.New, macKey))
	case 3:
		err = k.validateHMAC(hmac.New(sha256.New, macKey))
	default:
		err = fmt.Errorf("unknown key format version: %d", k.Version)
	}
	return
}

// Encrypt encrypts the key and updates the HMAC
func (k *Key) Encrypt(random io.Reader, password []byte) error {
	// Set a sensible value for an unset version number
	if k.Version == 0 {
		k.Version = 3
	} else if k.Version > 3 || k.Version < 0 {
		return fmt.Errorf("unknown putty key version")
	}
	if k.Encryption != "none" {
		return fmt.Errorf("decrypt the key first, then encrypt it")
	}
	if len(password) == 0 {
		return fmt.Errorf("no password provided")
	}
	if k.keySize == 0 {
		k.keySize = len(k.PrivateKey)
	}
	k.PrivateKey = addPadding(k.PrivateKey)
	k.padded = true

	if k.Version == 3 && k.KeyDerivation == "" {
		k.KeyDerivation = "Argon2id"
		k.Argon2Memory = 8192
		k.Argon2Passes = 13
		k.Argon2Parallelism = 1
		salt := make([]byte, 16)
		random.Read(salt)
		k.Argon2Salt = salt
	}

	cipherKey, cipherIV, macKey, err := k.deriveKeys(password)
	if err != nil {
		return err
	}

	k.Encryption = "aes256-cbc"
	err = k.calculateHMAC(password)
	if err != nil {
		return err
	}

	err = encryptCBC(cipherKey, cipherIV, macKey, k.PrivateKey)
	if err != nil {
		return err
	}
	return nil
}
