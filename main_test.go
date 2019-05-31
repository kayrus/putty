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

var (
	keysWithPassword = []struct {
		content          string
		encryptionMethod string
		password         string
	}{
		{
			// puttygen -t rsa -b 512 -C "a@b" -o pass.ppk
			content: `PuTTY-User-Key-File-2: ssh-rsa
Encryption: aes256-cbc
Comment: a@b
Public-Lines: 2
AAAAB3NzaC1yc2EAAAABJQAAAEEAorCK9W8rDXirgPGwRLXZOQYlASsqjMQ2t9xQ
k1Aw+f8JJ7qYaFEwpcWGWf/br3n83FIl18r3AIIIU/WjiUIlbw==
Private-Lines: 4
ZJsVbNlwaPjIrs9KiYIWTaBXifB7jJH6CdADEd5DV2jhQk+xi5PWdNf1uLnlAPpE
0OvpMjU66gTsjuirmyi53nRFtqoCjjm7waf3x9lbNDoVUhWTV+JK4NTR2T0nnjnO
D51wcjdd2aEcpvif7LNSksRJZkJuMJVt2o68SDM4kQlQivc9lBf3HR8t3yxxjNV2
lmHm9dFVUGKo7nh/eyWzo1AibICdfMnc4pc69FstgM5Nuetl1Lq157XFvKKZyisd
Private-MAC: 7f8e59f1f2268600076dbdef55c6acb91c6c1578`,
			encryptionMethod: "rsa",
			password:         "testkey",
		},
		{
			// puttygen -t ecdsa -b 256 -C "a@b" -o pass.ecdsa.ppk
			content: `PuTTY-User-Key-File-2: ecdsa-sha2-nistp256
Encryption: aes256-cbc
Comment: a@b
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGascQ2IAWOr
eeFFvfkMPrEzIv9YzW4xPAhdnKcHmpBaCGnru7j5YilLdanHF1j3E65/nsUJOAt8
+j3eSrULEEE=
Private-Lines: 1
61hg1CoGUcsBB8u5TD48gzdmxMDP6+D+GhD4UzDisD+iKehU8PatDdQIVtRUY8ja
Private-MAC: 07bafdfa36c3184d01f79e0db8f668e761ab4e20`,
			encryptionMethod: "ecdsa",
			password:         "testkey",
		},
		{
			// puttygen -t ecdsa -b 256 -C "a@b" -o pass.ecdsa.ppk
			content: `PuTTY-User-Key-File-2: ssh-dss
Encryption: aes256-cbc
Comment: a@b
Public-Lines: 18
AAAAB3NzaC1kc3MAAAEBAMLTkybOY3kUIdFXaZq2osYuxwaqYum65goAUvZmanCG
Mim9TRNCw+DA+MiZduKgBcXPuTFZyVNkDDodWW6KhHgT3sMHsIA5Mh9XvyrtQKvv
1yOGeHUOwjxohQQm5NVr5CQcpkyd3x8bHcaiFEaTZDuw7GksbW2lsa4lyv0GFUc8
9gaLDMC9ipOwFER2pP7AlIg9qj5Qgrj2z/KkZQGVPObae2L+oqkfwD8rX5cHWzie
ARxQDfVhOagF32Jaxt4+QODGD00cN1oCRtkOUD5HPy96HvOx0xwhDrAU9YQPgl2q
SaB3Bq6s2C+9Dn01ugQ7ik99cDhFp2HefwUcCGqb8zMAAAAVAOXfaExPDDBbC0JB
0JQpnyRyfTcBAAABAFKVIBswBAA845IZ8fuMcA8JXzLbJqq5IyYL5P9nDNZFMbSm
5pJbpV5msnYfJBgeFhX4buXbve7ehctIpVgkShWIIMgT5mKQv6BvaOchkIFwKdQE
dypPmJOgSCiij3000TVzky4A6KZZI7+XtC+rtjnDjuk6v2dn4hVa2khW/Adr/eHU
RCDfez1bJobglBs9xtYIOmw1xZzaRQi1nKBUimfxFEGMRinhCss+1qh73K6HRvTC
9kEgJ4Lrn6NJQFtlFB4P2PEcqfKp3EsbGGlV52XLIv5fHvtt2xR24k2oebcS2fq+
dXEg5Sg9AnOY7t3KwMWrv+2KRC7XGh+55+pfOdMAAAEBAKplqzkQyLR+55/DJC9s
JeAsBHhws+xCLkX1waKCrCVjkhsz35WrEGIgsboJ2I9KIZO3be7XReyMLMEAcBBf
f0RZ6ZlsbqPByoOBYUdahlwLc/m71pUs6X6yLv9MLW46BTmTneZRGtLTdK2ouSbW
q1gbY2p8dnR2TrCThmde+2U4RzFvI30Layu1Amst6kt9Zcz3eV+lxpR7vNFgq4kB
2QgVgh8e7keg1ebzl0nRBk4+kFZhLOT5nY4aJ1TRiD4TGuSugBQSfRW60LOf4R28
aWxu7A5Jbsm8fATR3N0bWgOQWc4cRC7t3mb0Xrt2bW2amcWEkZF57uV5Ldv7aKAK
MXs=
Private-Lines: 1
IcDcTw/elt2xwgWoweaz0wb4mHVCLc3w64YXc8hxouE=
Private-MAC: 30b6587e0f0e4baf38895408d5d6c903add96816`,
			encryptionMethod: "ecdsa",
			password:         "testkey",
		},
		{
			// puttygen -t ecdsa -b 384 -C "a@b" -o pass.ecdsa.ppk
			content: `PuTTY-User-Key-File-2: ecdsa-sha2-nistp384
Encryption: aes256-cbc
Comment: a@b
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBMLZhNzFeAQG
bMx96v8vL/a+bI/nF1/8iN6cXgGph/IodS1G/ikq75ufDbKH+0ZmKnlP3j08Vtit
pkdmmIkTukvrrLlYnhN4BY5qyvy259a3j6RUGvYzYA33t5FQW9PCOQ==
Private-Lines: 2
tQBqst/bUEfUTKGbBv17b1Mb38AYaUT3Wposs+ZydBc1uHg54tM+kzCuon+4/36o
dRKoYQjl8YUcKtPkihNRKw==
Private-MAC: 898b91d24130483ba2a5cf478ed65386b325aba8`,
			encryptionMethod: "ecdsa",
			password:         "testkey",
		},
		{
			// puttygen -t ecdsa -b 521 -C "a@b" -o pass.ecdsa.ppk
			content: `PuTTY-User-Key-File-2: ecdsa-sha2-nistp521
Encryption: aes256-cbc
Comment: a@b
Public-Lines: 4
AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAFIXU1DQU+c
yADEnp95G7N7zxNQ2Bj7bAz5cAIxEcBuGd707/Z96eZGsF4din4Grfse4gFmKsNO
Uzdo0QPZ4BDdLACe5gysjxHi5Qa65y79PjpOo8qYCDIocf/aeX24Q8MlnbNK4lHO
M8j6NJi2tQsp/Vaf1h+FHViV4meyanYyjZrljQ==
Private-Lines: 2
7KW71RQdH1EQD2nBdI7y8JmufwoX2bupP8QCcS9/bS+pZQCGu0XuzBd8YswfUl9H
fKT7hsBrywG5Z3ujmLerhf1bCIKotolmpxGQyPE0bCE=
Private-MAC: 586871c9dad8859f3d9b6efad81d3c26d923040c`,
			encryptionMethod: "ecdsa",
			password:         "testkey",
		},
		{
			// puttygen -t ed25519 -b 256 -C "a@b" -o pass.ed25519.ppk
			content: `PuTTY-User-Key-File-2: ssh-ed25519
Encryption: aes256-cbc
Comment: a@b
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIMb3N9pbqMpSJRFb/WF8Wcz80SiW8emW3aLFqdRA
rs+r
Private-Lines: 1
i6a/aAknwkK/cVT8nW9zcsOJDvOdPvfBlx0suOtygmSbz9L4yoBAZZu8AHxWDSgm
Private-MAC: 8fa9edfc1b94bec840ee1526d290bf1d8eb9fbc9`,
			encryptionMethod: "ed25519",
			password:         "testkey",
		},
	}
)

func Test_readHeader(t *testing.T) {

	header := "PuTTY-User-Key-File-2: ssh-rsa"
	expectedHeaderFormat := "PuTTY-User-Key-File-2"
	reader := strings.NewReader(header)
	h, err := readHeader(bufio.NewReader(reader))

	if err != nil {
		t.Errorf("got=[%s], expected=[%s]", h, expectedHeaderFormat)
	}

	header = ""
	reader = strings.NewReader(header)
	_, err = readHeader(bufio.NewReader(reader))
	if err == nil {
		t.Errorf("Header empty")
	}

	header = `
	PuTTY-User-Key-File-2: ssh-rsa`
	reader = strings.NewReader(header)
	_, err = readHeader(bufio.NewReader(reader))
	if err == nil {
		t.Errorf("No newlines allowed in header.")
	}

	header = "PuTTY-User-Key-File-2:"
	reader = strings.NewReader(header)
	_, err = readHeader(bufio.NewReader(reader))
	if err == nil {
		t.Errorf("Missing algorithm in header")
	}

	header = "PuTTY-User-Key-File-2:_ssh-rsa"
	reader = strings.NewReader(header)
	_, err = readHeader(bufio.NewReader(reader))
	if err == nil {
		t.Errorf("Expecting whitespace after ':' in header.")
	}

	header = ""
	reader = strings.NewReader(header)
	_, err = readHeader(bufio.NewReader(reader))
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

func TestParseRawPrivateKey(t *testing.T) {
	for _, encryptedKey := range keysWithPassword {
		key, err := New([]byte(encryptedKey.content))
		if err != nil {
			t.Errorf("error loading key")
		}

		_, err = key.ParseRawPrivateKey([]byte("testkey"))
		if err != nil {
			t.Errorf("error decrypting key")
		}
	}
}
