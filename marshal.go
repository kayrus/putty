package putty

import (
	"bytes"
	"crypto/aes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math/big"
	"reflect"
)

func marshal(val interface{}) (data []byte, err error) {
	v := reflect.ValueOf(val).Elem()
	buf := bytes.NewBuffer([]byte{})

	err = writeField(v, buf)
	data = buf.Bytes()
	return
}

func addPadding(data []byte) []byte {
	keySize := len(data)
	if keySize%aes.BlockSize == 0 {
		return data
	}
	sha := sha1.Sum(data)
	padSize := aes.BlockSize - keySize&(aes.BlockSize-1)
	data = append(data, make([]byte, padSize)...)
	copy(data[keySize:], sha[:])
	return data
}

func writeField(v reflect.Value, dst *bytes.Buffer) error {
	fieldType := v.Type()

	switch fieldType.Kind() {
	case reflect.Struct:
		for i := 0; i < fieldType.NumField(); i++ {
			if fieldType.Field(i).PkgPath != "" {
				return fmt.Errorf("struct contains unexported fields")
			}

			err := writeField(v.Field(i), dst)
			if err != nil {
				return err
			}
		}
		return nil
	}

	switch fieldType {
	case reflect.TypeOf(string("")):
		err := writeString2(dst, v.String())
		if err != nil {
			return err
		}
	case reflect.TypeOf([]byte(nil)):
		err := writeBytes2(dst, v.Bytes())
		if err != nil {
			return err
		}
	case reflect.TypeOf(new(big.Int)):
		switch val := (v.Interface()).(type) {
		case *big.Int:
			err := writeBigInt2(dst, val)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unable to set big int")
		}
	default:
		return fmt.Errorf("unknown type %s", fieldType)
	}

	return nil
}

func writeBytes1(dst *bytes.Buffer, data []byte, length uint16) error {
	//length := uint16(len(data) * 8)
	// write 4 bytes (data size) of the next element size
	err := binary.Write(dst, binary.BigEndian, &length)
	if err != nil {
		return err
	}

	_, err = dst.Write(data)

	return err
}

func writeBigInt1(dst *bytes.Buffer, data *big.Int) error {
	b := data.Bytes()

	return writeBytes1(dst, b, uint16(data.BitLen()))
}

func writeInt32(dst *bytes.Buffer, val uint32) error {
	return binary.Write(dst, binary.BigEndian, &val)
}

func writeBytes2(dst *bytes.Buffer, data []byte) error {
	length := uint32(len(data))
	// write 4 bytes (data size) of the next element size
	err := binary.Write(dst, binary.BigEndian, &length)
	if err != nil {
		return err
	}

	_, err = dst.Write(data)

	return err
}

func writeString2(dst *bytes.Buffer, data string) error {
	return writeBytes2(dst, []byte(data))
}

func writeBigInt2(dst *bytes.Buffer, data *big.Int) error {
	b := data.Bytes()
	for (len(b) > 8 && b[0] >= 128) || len(b) == 2 || len(b) == 3 {
		b = append([]byte{0}, b...)
	}
	return writeBytes2(dst, b)
}
