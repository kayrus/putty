package putty

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"reflect"
)

func unmarshal(data []byte, val interface{}, enc bool) error {
	v := reflect.ValueOf(val).Elem()
	buf := bytes.NewReader(data)

	err := parseField(v, buf)
	if err != nil {
		return err
	}

	// check key block size
	err = checkGarbage(buf, enc)
	if err != nil {
		return fmt.Errorf("wrong key size: %s", err)
	}

	return nil
}

func parseField(v reflect.Value, src *bytes.Reader) error {
	fieldType := v.Type()

	switch fieldType.Kind() {
	case reflect.Struct:
		for i := 0; i < fieldType.NumField(); i++ {
			if fieldType.Field(i).PkgPath != "" {
				return fmt.Errorf("struct contains unexported fields")
			}

			err := parseField(v.Field(i), src)
			if err != nil {
				return err
			}
		}
		return nil
	default:
	}

	switch fieldType {
	case reflect.TypeOf(string("")):
		parsedString, err := readString(src)
		if err != nil {
			return err
		}
		v.Set(reflect.ValueOf(parsedString))
	case reflect.TypeOf([]byte(nil)):
		parsedBytes, err := readBytes(src)
		if err != nil {
			return err
		}
		v.Set(reflect.ValueOf(parsedBytes))
	case reflect.TypeOf(new(big.Int)):
		parsedInt, err := readBigInt(src)
		if err != nil {
			return err
		}
		v.Set(reflect.ValueOf(parsedInt))
	default:
		return fmt.Errorf("unknown type %s", fieldType)
	}

	return nil
}

func readBytes(src *bytes.Reader) ([]byte, error) {
	var length uint32
	// read 4 bytes (uint32 size) of the next element size
	err := binary.Read(src, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}

	// get the current reader position
	pos, err := src.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	// check next element size
	if int64(length)+pos > src.Size() {
		return nil, fmt.Errorf("the element length %d is out of range", length)
	}

	buf := make([]byte, length)
	n, err := io.ReadFull(src, buf)
	if err != nil {
		return nil, err
	}

	if n != int(length) {
		return nil, fmt.Errorf("expected to read %d, but read %d", length, n)
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
