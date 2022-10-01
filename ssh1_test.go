package putty

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

var SSH1unencrypted = `
	U1NIIFBSSVZBVEUgS0VZIEZJTEUgRk9STUFUIDEuMQoAAAAAAAAAAAQABACyVhLTcHAKqu8YkxMR
	fuq2ZtvfBAZ/ZD+TT6+sjhLSTQ+YjO2twb3Ku8eYiTKFcT40mSaMhq0Ei9YG1iGyLdDJLUF4s4HO
	ua138J1SQJac1BDzWBy+PUqoeRk2TuvvwVFAUZ8ZlMz8suw7WvWWYnkqPVCCiHVDNLm9awpBP1y8
	lQAGJQAAABByc2Eta2V5LTIwMjIwOTE4u3i7eAP+MDLwVNJHy4gk8eKPiDAjwphXGa4PmA1BnW97
	lmuWYloENxFU/odjukCWz0esyh6bMM9yM9FfMalAw5PRwXQqlsg6xz/LY7tguSxtlBDxwluOnCcv
	7EereEdcSGTTB5iEZOcxRJrvMgIUQlHSzc9uDAnPslFOuADLrYeR7/uUhkUB/jGTA5jF6NDanWN2
	xyRCO1dumGfkhexTqGRA5WtUz/DxHZch1iD3Ek8dC0OF2jr7f8Ig3PbC4RfHyNd0pOZNTK4CALwe
	cv5UIIslQKzt3POQpi3P8YAaE7oed/Di6m/325lS6AB4bfWIaAQeywg9Nep/meiS1AuDslwBl/5s
	+JbXC5MCAPKv8Ukjifk78IWznkGHdFN+Jno3wEbLWeaUDNBNq0B64vm9LchpKHPo4VcsZvh7/WOj
	mraBgaKTVpCa6lJ5wDcAAAAA`
var SSH1encrypted = `
	U1NIIFBSSVZBVEUgS0VZIEZJTEUgRk9STUFUIDEuMQoAAwAAAAAAAAQABACyVhLTcHAKqu8YkxMR
	fuq2ZtvfBAZ/ZD+TT6+sjhLSTQ+YjO2twb3Ku8eYiTKFcT40mSaMhq0Ei9YG1iGyLdDJLUF4s4HO
	ua138J1SQJac1BDzWBy+PUqoeRk2TuvvwVFAUZ8ZlMz8suw7WvWWYnkqPVCCiHVDNLm9awpBP1y8
	lQAGJQAAABByc2Eta2V5LTIwMjIwOTE4jGWS/2YMLF+EayIjJtsJYvfV5ZRhfWwvW6uZm9I+6Qyq
	Jg2Rts81YB7iwlMBBEWxdHi+gOIx3p5RpP48QlXGXnv/8vv62yR/iadL802Rto6uIwN9WA8KGZ/a
	+pe64e8xa3sYX9622XCT4pA8lB3Mb9+AiBzra+GSH8wLlU6k9IZusvCwK+/ToBlFCrWAeKLKHNBK
	VuR2QjspFldSXj46AsUmTrFYgATQHCW8BkfMtZFYTFFi+ZkgrZMOM2hg0p4gVMNVw5YQLPdiyLjm
	SKxOEFB/z1YygVd5PKS9rF3fw2UeSSXq02hoGEotZwmRMa7QAN4hJ7N/8KlDB9M1768mcOY9TD2j
	Dv3NsaCgX0rD8+juS+L59QZyP9gOcOSIPq2o5etDcDKdZFPLDYKqAbKQK/As/5+1WRXfLy/XjTfN
	Psg/DuQZf57RNQ3+y9wy2yqK`

var SSH1Public = "000000077373682d72736100000001250000008100b25612d370700aaaef189313117eeab666dbdf04067f643f934fafac8e12d24d0f988cedadc1bdcabbc798893285713e3499268c86ad048bd606d621b22dd0c92d4178b381ceb9ad77f09d5240969cd410f3581cbe3d4aa87919364eebefc15140519f1994ccfcb2ec3b5af59662792a3d508288754334b9bd6b0a413f5cbc95"
var SSH1Private = "000000803032f054d247cb8824f1e28f883023c2985719ae0f980d419d6f7b966b96625a04371154fe8763ba4096cf47acca1e9b30cf7233d15f31a940c393d1c1742a96c83ac73fcb63bb60b92c6d9410f1c25b8e9c272fec47ab78475c4864d307988464e731449aef3202144251d2cdcf6e0c09cfb2514eb800cbad8791effb9486450000004100f2aff1492389f93bf085b39e418774537e267a37c046cb59e6940cd04dab407ae2f9bd2dc8692873e8e1572c66f87bfd63a39ab68181a29356909aea5279c0370000004100bc1e72fe54208b2540aceddcf390a62dcff1801a13ba1e77f0e2ea6ff7db9952e800786df58868041ecb083d35ea7f99e892d40b83b25c0197fe6cf896d70b930000004031930398c5e8d0da9d6376c724423b576e9867e485ec53a86440e56b54cff0f11d9721d620f7124f1d0b4385da3afb7fc220dcf6c2e117c7c8d774a4e64d4cae"
var SSH1PublicKey = "1024 37 125231955839861145597959941566719353978850591507101309939104935173887041843256466484940189588914165868561229567474080040371609970058249262542234488820048185261582821399489992085432366135601216753217583542250921463784984173203393090111095957397902456223378197593025272833066640581329273146588092056412215884949 rsa-key-20220918\r\n"

func TestSSH1LoadEncrypted(t *testing.T) {
	k := Key{}
	err := k.LoadSSH1WithPassword(b64decode(SSH1encrypted), "testit")
	if err != nil {
		panic(err)
	}

	if fmt.Sprintf("%02x", k.PublicKey) != SSH1Public {
		panic("Error decoding public key")
	}
	if fmt.Sprintf("%02x", k.PrivateKey) != SSH1Private {
		panic("Error decoding private key")
	}

	priv, _ := k.saveSSH1([]byte("testit"), bytes.NewReader([]byte{111, 130}))
	if !bytes.Equal(priv, b64decode(SSH1encrypted)) {
		panic("Encoded SSH1 mismatch")
	}

	priv, _ = k.saveSSH1(nil, bytes.NewReader([]byte{187, 120}))
	if !bytes.Equal(priv, b64decode(SSH1unencrypted)) {
		panic("Encoded SSH1 mismatch")
	}

	k.PrivateKey = []byte{}
	pub, _ := k.MarshalSSH1()
	if string(pub) != SSH1PublicKey {
		panic("Error encoding public key")
	}
}

func TestSSH1Load(t *testing.T) {
	k := Key{}
	err := k.LoadSSH1(b64decode(SSH1unencrypted))
	if err != nil {
		panic(err)
	}

	if fmt.Sprintf("%02x", k.PublicKey) != SSH1Public {
		panic("Error decoding public key")
	}
	if fmt.Sprintf("%02x", k.PrivateKey) != SSH1Private {
		panic("Error decoding private key")
	}
}

func b64decode(str string) []byte {
	noWhiteSpace := strings.NewReplacer("\r", "", "\n", "", "\t", "", " ", "")
	dat, _ := base64.StdEncoding.DecodeString(noWhiteSpace.Replace(str))
	return dat
}
