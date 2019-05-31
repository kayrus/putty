package putty

import (
	"bufio"
	"strings"
	"testing"
)

const (
	keyContent = `PuTTY-User-Key-File-2: ssh-rsa
Encryption: none
Comment: a@b
Public-Lines: 2
AAAAB3NzaC1yc2EAAAABJQAAAEEAqexbeyaaBw2rFZc2vwg4DqjOo6fQyOdfo9O2
20y96bUlHRYzRWmIDzHC5gZBzlHQ6M56dprxhCJbsIQig+sQ+w==
Private-Lines: 4
AAAAQBb2bTonz6AWmpQ3B2XsWpoyfMoB68gfREaSO04RShipjkwri4K8DmSX1+Nb
xUyFO7aS7rpsO3mitZtYt3bS3z0AAAAhANvUiZew5AgUZ3peSzSqaVch4vapHml4
7nx03dx4aS5JAAAAIQDF4bDGZq973zNxW62MVA6MsxKdNsIDILMFvhXFNc/VIwAA
ACEAgd1SYGV2aEEMQaMGQ4CnjQeiAuZL4z7OVTBTrtGap1A=
Private-MAC: 3c3a9bd98e8e912f6163be95321676b6103aaed8`
)

func Test_readHeader(t *testing.T) {

	header := "PuTTY-User-Key-File-2: ssh-rsa"
	expectedHeaderFormat := "PuTTY-User-Key-File-2"
	reader := strings.NewReader(header)
	h, err := readHeaderFormat(bufio.NewReader(reader))

	if err != nil {
		t.Errorf("got=[%s], expected=[%s]", h, expectedHeaderFormat)
	}

	header = ""
	reader = strings.NewReader(header)
	_, err = readHeaderFormat(bufio.NewReader(reader))
	if err == nil {
		t.Errorf("Header empty")
	}

	header = `
	PuTTY-User-Key-File-2: ssh-rsa`
	reader = strings.NewReader(header)
	_, err = readHeaderFormat(bufio.NewReader(reader))
	if err == nil {
		t.Errorf("No newlines allowed in header.")
	}

	header = "PuTTY-User-Key-File-2:"
	reader = strings.NewReader(header)
	_, err = readHeaderFormat(bufio.NewReader(reader))
	if err == nil {
		t.Errorf("Missing algorithm in header")
	}

	header = "PuTTY-User-Key-File-2:_ssh-rsa"
	reader = strings.NewReader(header)
	_, err = readHeaderFormat(bufio.NewReader(reader))
	if err == nil {
		t.Errorf("Expecting whitespace after ':' in header.")
	}

	header = ""
	reader = strings.NewReader(header)
	_, err = readHeaderFormat(bufio.NewReader(reader))
	if err == nil {
		t.Errorf("Header empty")
	}

}

func Test_decodeFields(t *testing.T) {
	// Generated using: puttygen -t rsa -b 2048 -C "a@b" -o a.ppk
	privateKeyContent := `PuTTY-User-Key-File-2: ssh-rsa
Encryption: none
Comment: a@b
Public-Lines: 6
AAAAB3NzaC1yc2EAAAABJQAAAQEAu6/eYNOqU2q1xsyPm9yJpAEyEuWfAD8b8W/u
yt5BC/L8ZRSN8RnzQH1OXt7uHvpFXS9oDqCknwWCCYubaMUKXwTqz3W/8TCspRLK
nc09RG0ZeR4qNXl6dezOrbN8iIoAOvNhdKfURA4ukMUvQF2hBgMcSw5c+gMi3+E7
YpQaPLQIILhrzEO+ZwmJ3Hz4vo1iZlhgw56zoijd/GBJk3a7VfrQa7MuCToJMmKV
RbZofmOEt9J6Vj2uFzreG1eWQ6E/b0TXv88JzrRn/QfvqIX7WEwZwkvrM780w4xe
IhgzK95euvXAuV/u7lL1IDXQK56AyIg0TQz5f2ZL9gn5DIWfwQ==
Private-Lines: 14
AAABAQC2nUcSGg2BmEIpNbwo8kC7P279oSUU/yIbWCab3yqIKrBiWTAo2vqD74qF
0fxxKtu0nNPyjnaoj7zLBF/bj0hcc3yuLWDO/u0q/Ybeudq/HgryYonu1w9d+yn1
HVaSr8jfaVfnH9VypgPLILhaTUK5vdZW3YrlatXS6PuCgkMKn6jMS2SXLJci+vpL
SZmBDYdTe0LmlGzMobNowEm3M/GmpAriODCbnMZf401BdJtMs2M0lZBb1uEJ3/95
rCMwhWRLeM6taGMW27RQvjcMWTD9D3Zy8DOe56Ql1/BlEBOkvIW6kZCR1otu1quB
WsDWwXrfkdpYoYbqOoTXYX7Htt89AAAAgQDn1gwflVaBRkTg4TXgv2wnkZNnA8b2
bpyawTAMreZ1R0xJK/UwOl3uYQGTrTBaOfiTQWUdmshS+JkvVzGjUO7MonJ+Le3q
iv8IcswND6kFTHWWi07euNLgbOqTx57i5RFoAI5KRecJHv9+lHabh3wOw+kwn8wQ
SNemGYViDHok0wAAAIEAzz/QlpuNocsJ0mbJrAGab774EW9NadMCg7oxuD6a4wb3
tPOu6Eteh9JiDqN44G55rw6awUCfnn8mIRVReXKbIQ15vgpSR6UarVOxRnbWoCQx
SXm/EFB+QPbZL7m3AzLSUNcY9zLqnZ1om5wh7nIUete640PwOv62DxuZRnnk3JsA
AACAHis2ePiHdJL4yzEzdbvLqmiM1nSmK74kxxHWT1dVHH3yKoRXJ5K8sw7+3xc/
Y5ONUplv3jwhWKyfARrWXz7q2/PC8GLTqNZamGLEhHQ3Hyy0PsaZksbZl60tP+Fi
edE9maSGzUQYxV/liqGFgyPHPBvYOh4lG64luZ+tqEh/PKQ=
Private-MAC: df8235a99cc5a0bbcd4a24642ccac67fe31ea382`

	reader := strings.NewReader(privateKeyContent)
	key, err := decodeFields(bufio.NewReader(reader))
	if err != nil {
		t.Errorf("Failed to parse private key")
	}

	expectedAlgorithmInHeader := "ssh-rsa"
	if key.Algo != expectedAlgorithmInHeader {
		t.Errorf("got=[%s], expected=[%s]", key.Algo, expectedAlgorithmInHeader)
	}

	expectedEncryption := "none"
	if key.Encryption != expectedEncryption {
		t.Errorf("got=[%s], expected=[%s]", key.Encryption, expectedEncryption)
	}

	expectedComment := "a@b"
	if key.Comment != expectedComment {
		t.Errorf("got=[%s], expected=[%s]", key.Comment, expectedComment)
	}

	expectedPrivateMAC := "df8235a99cc5a0bbcd4a24642ccac67fe31ea382"
	if key.PrivateMac != expectedPrivateMAC {
		t.Errorf("got=[%s], expected=[%s]", key.PrivateMac, expectedPrivateMAC)
	}

	privateKeyContent = `PuTTY-User-Key-File-1: ssh-rsa
Encryption: none
Comment: a@b`

	reader = strings.NewReader(privateKeyContent)
	_, err = decodeFields(bufio.NewReader(reader))
	if err == nil {
		t.Errorf("Should have identified old key format")
	}

	privateKeyContent = `PuTTY-User-Key-File-2: ssh-unknown
Encryption: none
Comment: a@b`

	reader = strings.NewReader(privateKeyContent)
	_, err = decodeFields(bufio.NewReader(reader))
	if err == nil {
		t.Errorf("Invalid key algorithm")
	}

}

func checkLoadingFromByteSlice(keyContent string, t *testing.T) {

	key := &Key{}
	err := key.Load([]byte(keyContent))
	if err != nil {
		t.Errorf("error loading Key fields")
	}

	expectedAlgorithmInHeader := "ssh-rsa"
	if key.Algo != expectedAlgorithmInHeader {
		t.Errorf("got=[%s], expected=[%s]", key.Algo, expectedAlgorithmInHeader)
	}

	expectedEncryption := "none"
	if key.Encryption != expectedEncryption {
		t.Errorf("got=[%s], expected=[%s]", key.Encryption, expectedEncryption)
	}

	expectedComment := "a@b"
	if key.Comment != expectedComment {
		t.Errorf("got=[%s], expected=[%s]", key.Comment, expectedComment)
	}

	expectedPrivateMAC := "3c3a9bd98e8e912f6163be95321676b6103aaed8"
	if key.PrivateMac != expectedPrivateMAC {
		t.Errorf("got=[%s], expected=[%s]", key.PrivateMac, expectedPrivateMAC)
	}
}

func TestKey_Load(t *testing.T) {
	key := &Key{}
	err := key.Load([]byte(keyContent))
	if err != nil {
		t.Errorf("error loading Key fields")
	}
	validateFields(key, t)
}

func TestNew(t *testing.T) {
	key, err := New([]byte(keyContent))
	if err != nil {
		t.Errorf("error loading Key fields")
	}
	validateFields(key, t)
}

func validateFields(key *Key, t *testing.T) {
	expectedAlgorithmInHeader := "ssh-rsa"
	if key.Algo != expectedAlgorithmInHeader {
		t.Errorf("got=[%s], expected=[%s]", key.Algo, expectedAlgorithmInHeader)
	}

	expectedEncryption := "none"
	if key.Encryption != expectedEncryption {
		t.Errorf("got=[%s], expected=[%s]", key.Encryption, expectedEncryption)
	}

	expectedComment := "a@b"
	if key.Comment != expectedComment {
		t.Errorf("got=[%s], expected=[%s]", key.Comment, expectedComment)
	}

	expectedPrivateMAC := "3c3a9bd98e8e912f6163be95321676b6103aaed8"
	if key.PrivateMac != expectedPrivateMAC {
		t.Errorf("got=[%s], expected=[%s]", key.PrivateMac, expectedPrivateMAC)
	}
}
