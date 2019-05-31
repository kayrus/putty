package putty

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
)

func readBytes(src *bytes.Reader) ([]byte, error) {
	var len uint32

	// read 4 bytes (uint32 size) of the next element size
	err := binary.Read(io.LimitReader(src, int64(4)), binary.BigEndian, &len)
	if err != nil {
		return nil, err
	}

	// get the current reader position
	pos, err := src.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	// check next element size
	if int64(len)+pos > src.Size() {
		return nil, fmt.Errorf("the element length %d is out of range", len)
	}

	buf := make([]byte, len)
	n, err := io.ReadFull(src, buf)
	if err != nil {
		return nil, err
	}

	if uint32(n) != len {
		return nil, fmt.Errorf("expected to read %d, but read %d", len, n)
	}

	return buf, nil
}

func readString(src *bytes.Reader) (string, error) {
	b, err := readBytes(src)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func readBigInt(src *bytes.Reader) (*big.Int, error) {
	b, err := readBytes(src)
	if err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(b), nil
}

func checkGarbage(src *bytes.Reader, encrypted bool) error {
	pos, err := src.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	if encrypted {
		// normalize the size of the decrypted part (should be % aes.BlockSize)
		pos = pos + aes.BlockSize - pos&(aes.BlockSize-1)
	}

	// check key size
	if src.Size() != pos {
		return fmt.Errorf("expected %d, got %d", pos, src.Size())
	}

	return nil
}
