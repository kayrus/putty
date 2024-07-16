package putty

import (
	"bufio"
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
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

type testKeyStruct struct {
	content  string
	keyType  string
	password []byte
	data     interface{}
}

var (
	mac1, mac2   []byte
	keysFixtures []testKeyStruct
)

func init() {
	mac1, _ = hex.DecodeString("3c3a9bd98e8e912f6163be95321676b6103aaed8")
	mac2, _ = hex.DecodeString("df8235a99cc5a0bbcd4a24642ccac67fe31ea382")

	dsaP, _ := new(big.Int).SetString("24594562591148674955193935530570345698901351673115514528850649708585499534112253610063676118481975411425473555170006092361522567122668561166623600473338556612006266904734584520036147901134857358698958891337509539840397725282694053771143291815546131811329906604343196079953386684245940025973122612572623286633577598913988451237865018093641985572774958578455846290160433526300387888405060531817175364632586536057657667465336393991275791245035916446578505777445647787250353018737479407834863073244575186642619947916919893272642340891779424822336371882593459817314757590432914231351510355118493996526096415995901691818803", 10)
	dsaQ, _ := new(big.Int).SetString("1312341038342200669065145856275284506462910232321", 10)
	dsaG, _ := new(big.Int).SetString("10425077490021224161949597305729551331605748188798282297372931992795679890533253191063851317774978177087779792313915641092243367750810044491724052104552811663852087628398546468515716758181439573025733351734712399668145973555365229762144691787113025266081984796617297840056005672890746877901282842489089172477827905313991095991925328443157735824309346126295789077407934223177070081244875098862033746719850130865721824549860620047834045903705777084948010434133428686539181823369981863045754945910010043595598173308172093626744719830300869248812222241319999935223546737700715574148072183411259304981353771500265250175443", 10)
	dsaY, _ := new(big.Int).SetString("21510646617536686970256301962113811051397758140195234090460194930132038549590435491244976282798444518550747368745775628925406182046673364658952325925163405035564468078377990474727147614887717599605417338252450798540320708163986733717533122922047528385190165550782351240652858387386313772718064917332808821631800782888953175646687372284116533887062414252814237371365623131439296930507968790703639461812161116142375599044257673213057247217469031149630486664054488124298907613896781452876902366817780475672748311909538129167693858987730507482184614249830095325205465687346021497797754795120320928445244272698895964451195", 10)
	dsaX, _ := new(big.Int).SetString("189340186621154930140334018913803473857861157014", 10)
	dsaKey := &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: dsaP,
				Q: dsaQ,
				G: dsaG,
			},
			Y: dsaY,
		},
		X: dsaX,
	}

	rsaN, _ := new(big.Int).SetString("8520746803670459111964735264302364864406603319706722291382206884740918720975597863537943632699025487407803452238155180426869496108764232229987590678390127", 10)
	rsaD, _ := new(big.Int).SetString("4375518628911857381819728919506619795235823326335884419898971102975066370230617515168937792367348653574766837811133440634746446236118948255351252506463093", 10)
	rsaPrimeA, _ := new(big.Int).SetString("96613721054719714377323864891194620466947836547220293140459277308802606823211", 10)
	rsaPrimeB, _ := new(big.Int).SetString("88193961589001532442890792050520827586269248973933145286873718573717401086157", 10)
	rsaDp, _ := new(big.Int).SetString("13055908250637799240178900660972246009047004938813553127089091528216568489623", 10)
	rsaDq, _ := new(big.Int).SetString("26219826418351806942481046285289975768890857803061205355557051467861930052641", 10)
	rsaQinv, _ := new(big.Int).SetString("90518500249146741801779803717894162115106259819578908134048653601260005033042", 10)
	rsaKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: rsaN,
			E: 37,
		},
		D: rsaD,
		Primes: []*big.Int{
			rsaPrimeA,
			rsaPrimeB,
		},
		Precomputed: rsa.PrecomputedValues{
			Dp:        rsaDp,
			Dq:        rsaDq,
			Qinv:      rsaQinv,
			CRTValues: []rsa.CRTValue{},
		},
	}
	rsaKey.Precompute() // precompute n,p,q private modulus for CRT with Montgomery precomputed constants

	rsa2048N, _ := new(big.Int).SetString("25967111115904289073183561833662547569807833887670414054029756655277383180298119369791984179951095159243861045329504520276618295420687500854103113699968868025458341177364191133600455301580172781771353183147710953740515427628917527332516344741585308267548117567895976821479240362951145764725816854353006467624689451159554754504443606103722175343445340461369211625507075688499898051628145113573710079461409232565961586617052397600230077980603174203419790396776786830748108159352134838436200251743434264358097277418149173910690114990041701771397136433717681846642866469400270794717340347979079625102248472362584898465821", 10)
	rsa2048D, _ := new(big.Int).SetString("18971043536162738007904373721649797482985170003839959487113306203437464434940170520860585662084905263051346061772383179438248378545592833680126601522109791431694239522288134511448339103707198571665050130599697887683230521306629403370323368268720029294142299298882453731669530625114070818241178433349435428381748363590219678227448753611294842810581655356270769926060410258733333473695174209887220259221905950900395100577819149241234651559281741165124564697618881564799788576306983143583623357348716552228101941003138047213854034489157850376350498421485058855592433198552962407194608840169217681532801132349681830476033", 10)
	rsa2048PrimeA, _ := new(big.Int).SetString("175647912657839629385187093715137779950577519497624285063186225987469846648608910637515109768235899540057973103737324336107907638643777171827316157556466626748531154441518083656629794239760794004563711444483824988986571680924055367656794566071747585477599746867575310430131834343604265331156491830615381803349", 10)
	rsa2048PrimeB, _ := new(big.Int).SetString("147836149732607189337680383786692674666652100519928012034927325365258700686289916524775710532228255662511932089577947453286845378704437325268986424102345243425563973886582621925770875829428761009901216192490365624829026635852440887556494435547640564027395073961987521039232750098089829390657815728270725436329", 10)
	rsa2048Dp, _ := new(big.Int).SetString("131334584493829674210939212251444170940356595326946348489422992081785630946210269740301706272378408916512212277071579480938947434524940304729450137612944353732369076416340550428396627967880711485201268778156474601146054474271350308700213682671068967623767038401998763095774147097664522544862620644454972832285", 10)
	rsa2048Dq, _ := new(big.Int).SetString("6891365754201671779706327303177535149711188597103622026743716968901007531571718189468388783068454782015868174217016791580196112607260875973827815213278983149443794196003935333982788740084301461544596418329463768311834175695091427918352846492790971864804491370582600313942598098015844924065178861557090898393", 10)
	rsa2048Qinv, _ := new(big.Int).SetString("110813740759121094495870772370879033046355084589683649336385266956713688385144644089091571069396379501151545204563469635622943127313712587644247880671063259060443151779385923258484354383319230757635815163018068144951042011466267059177197095917355811673717871885446128102990706780818265345743683987056669334823", 10)
	rsa2048Key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: rsa2048N,
			E: 65537,
		},
		D: rsa2048D,
		Primes: []*big.Int{
			rsa2048PrimeA,
			rsa2048PrimeB,
		},
		Precomputed: rsa.PrecomputedValues{
			Dp:        rsa2048Dp,
			Dq:        rsa2048Dq,
			Qinv:      rsa2048Qinv,
			CRTValues: []rsa.CRTValue{},
		},
	}
	rsa2048Key.Precompute() // precompute n,p,q private modulus for CRT with Montgomery precomputed constants

	ecDsa256X, _ := new(big.Int).SetString("46440588512774590931736063230467913915182284012779182383533619500422092460122", 10)
	ecDsa256Y, _ := new(big.Int).SetString("3805648701849436066100068793961540825269458377130907545005086827909300817985", 10)
	ecDsa256D, _ := new(big.Int).SetString("27364976802251330859863334778865153913260419067928799613072475268713850318348", 10)
	ecDsa256Key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     ecDsa256X,
			Y:     ecDsa256Y,
		},
		D: ecDsa256D,
	}

	ecDsa384X, _ := new(big.Int).SetString("29990111091239627192665141980176542185683741491095927353923698474093483609776787457023321645830720432899228902516266", 10)
	ecDsa384Y, _ := new(big.Int).SetString("18671623354687946223865816665821866929613227373262947220106515362989193253901490069913353935925630019668174938817081", 10)
	ecDsa384D, _ := new(big.Int).SetString("2889949606013569690362264247910577554411207992641682332602011550384293294970872854035706361915044719593747685388818", 10)
	ecDsa384Key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     ecDsa384X,
			Y:     ecDsa384Y,
		},
		D: ecDsa384D,
	}

	ecDsa521X, _ := new(big.Int).SetString("4402647613186137418962458644805216088116725945293422204130228384201606379620975360267168868077720235906010278054415823980681644933726866421447586484944166188", 10)
	ecDsa521Y, _ := new(big.Int).SetString("2130482323314404387666653912266716286265983625697997927119424004060629190501633949869822692193763296916981545233653236718368283111555337775393159035752211853", 10)
	ecDsa521D, _ := new(big.Int).SetString("5861490831385977760498604046054515858972258068712574466879888582426090267695056372600709129575526893732420365360426250187633904340087080710548647491865731585", 10)
	ecDsa521Key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     ecDsa521X,
			Y:     ecDsa521Y,
		},
		D: ecDsa521D,
	}

	ed25519Key := &ed25519.PrivateKey{0x0, 0xd8, 0xf7, 0x75, 0xba, 0x68, 0xaa, 0xf3, 0xa4, 0xa6, 0xa3, 0x0, 0xde, 0xfd, 0x49, 0x84, 0xaa, 0xfd, 0x87, 0x9, 0xd, 0x22, 0x29, 0xe0, 0xf, 0x87, 0xa0, 0x5f, 0xd7, 0x3a, 0xda, 0xaf, 0xc6, 0xf7, 0x37, 0xda, 0x5b, 0xa8, 0xca, 0x52, 0x25, 0x11, 0x5b, 0xfd, 0x61, 0x7c, 0x59, 0xcc, 0xfc, 0xd1, 0x28, 0x96, 0xf1, 0xe9, 0x96, 0xdd, 0xa2, 0xc5, 0xa9, 0xd4, 0x40, 0xae, 0xcf, 0xab}

	keysFixtures = []testKeyStruct{
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
			keyType:  "rsa",
			password: []byte("testkey"),
			data:     rsaKey,
		},
		{
			// puttygen -t dsa -b 2048 -C "a@b" -o pass.dsa.ppk
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
			keyType:  "dsa",
			password: []byte("testkey"),
			data:     dsaKey,
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
			keyType:  "ecdsa256",
			password: []byte("testkey"),
			data:     ecDsa256Key,
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
			keyType:  "ecdsa384",
			password: []byte("testkey"),
			data:     ecDsa384Key,
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
			keyType:  "ecdsa512",
			password: []byte("testkey"),
			data:     ecDsa521Key,
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
			keyType:  "ed25519",
			password: []byte("testkey"),
			data:     ed25519Key,
		},
		{
			// puttygen -t rsa -b 2048 -C "a@b" -o rsa2048.ppk3
			content: `PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: a@b
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQDNsvsFOGphVzbJJAARnMs2E9p6jheXLTz7
dnZqNwZCYomnGurAPEuKmxD3GzdT+xP4BLFbAGDkeJHmjiNAPnbJf7G90u2zD28Y
J/c/krfKli50ZUOXG1a2DUhIvRM1GewOLhE7q5AOBHLQNFXvU9LR08t9H3u9xPJI
xNJjP6LqRGn+fP1xqlTbG3NTwCZMMXgXuAUhXGKaKbLUBN5SYmLvLTB6KzdHJQ6x
H9X+2Ul4hExje5L2X8miQqTxPloNtQNqpEtR2X7ecLyM9v3N1yDUK/NLwJ+PX8C8
KRbuBi5+xp+k62+btFXIk6CgGpsda/KleLmzTk5QJGLA9DfzrvAd
Private-Lines: 14
AAABAQCWR5StE7Jku1sDSJHkTDEKqSaNMxJ5GEvdS4bnwpuIFIWM2FV5bJOkB/Y1
EmUxrdXA9Wy9l2EyigPN9To7zWbrf6dTj66pizUW6NvyTjaIg4Ac+X6P/yEykDGn
Mru9p9qV4YIlngn4s7dN9W5zE0KKmbmpCD9XPXPlRiaO7AcSLujUHp7kPij2i9EL
vYRy0TS2g/HbQlBiaCS3+RI5K1UrwSP/MUFzmy319ZuI5XZUz7Z7OER4tgFi8qth
HqPkvBTnbi3ORIhRQQT+faEmKHwyDuXTXlITWj+1k3wY6sdr308OfRut6OcH417U
/YcZfBK6A3iZ9AJ/ih1Sqd0xCDkBAAAAgQD6IYSnq2k8LcGZvEtMt/izjFQICaJu
xvIbXBRsTqMmpNZiaDJU4i8NTbvfHBOSkx2Ip9dFQIVy9ijOuwg24VuXyCDY8Rzb
L/3Wkz/a1q4CJJSXgOpqQF60Dk8nYNRqEc2ykGkn/3GV/uqWbz0ohS1Wr55XiZeJ
fUSKmI72Yk6BVQAAAIEA0oaSAScm+gat8e6jAGpm1mHwf3iLI34NVgY3TzpL4kyz
Xk0OpxWMY5cgoXmWMnT1yCpun9SYBzyRhrfY8x7VPcNC9X96hNp/nIkp/FIWq/8M
TV2SIFcxidXpwMbGD8HXjAng+AkNYlK8ow/SDEkYsHWKuZsf99VqiHzgs5Y5U6kA
AACBAJ3N00Sgdv036FTLnU+NlF4N0kjhzjMDAPWRf9XvwkugiyB2tZ43rVCmXzgE
FzNeuOrWXPC7xh9Jfbg04rJv7sYZhSIIadTO3y3ToPXHpRNwg9pmC1BaQLMb0I5M
JUUNn5ASrFQki0/Ok5mwxz+QpktrvUuShkd/4e+sqHZ5mZ0n
Private-MAC: cceed3168be3c35863ebff8ff41457aa5ab449603b5660df1a4eea0201827c44`,
			keyType:  "ssh-rsa",
			password: nil,
			data:     rsa2048Key,
		},
		{
			// puttygen -t rsa -b 2048 -C "a@b" -o rsa2048.ppk3
			content: `PuTTY-User-Key-File-3: ssh-rsa
Encryption: aes256-cbc
Comment: a@b
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQDNsvsFOGphVzbJJAARnMs2E9p6jheXLTz7
dnZqNwZCYomnGurAPEuKmxD3GzdT+xP4BLFbAGDkeJHmjiNAPnbJf7G90u2zD28Y
J/c/krfKli50ZUOXG1a2DUhIvRM1GewOLhE7q5AOBHLQNFXvU9LR08t9H3u9xPJI
xNJjP6LqRGn+fP1xqlTbG3NTwCZMMXgXuAUhXGKaKbLUBN5SYmLvLTB6KzdHJQ6x
H9X+2Ul4hExje5L2X8miQqTxPloNtQNqpEtR2X7ecLyM9v3N1yDUK/NLwJ+PX8C8
KRbuBi5+xp+k62+btFXIk6CgGpsda/KleLmzTk5QJGLA9DfzrvAd
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 13
Argon2-Parallelism: 1
Argon2-Salt: 745d60746c67666afa47dbf23226c6c9
Private-Lines: 14
gqyGdBy5Nhxs5w00/7LUKZVUgwKVbTOcDjMh0ItVc5mWr7PoqtJhzrv7o8zEshHL
vviIJJ2NTo+whHEStAIaxqnJC0/KWSXvnhElH0+27+Yvkz+Z32hyczSbQp/fsBSA
3ZMQoyR92uAjG+gV7b0mqgsC0JWyaZYvippMNBHArZM8kaXdUYLDgmeXwIf7o/1I
QVh6RPanavcbDtafumHF2bIRCq5og1UoiaVyysgSMdrDpkkFvjHNwc4+xDEqnH3u
3v9PLIsolhbWUM7BwC1PnuCiaagbRvXoq+QTfdT5cbQw8lFngTgYT5NDkGJKMjB2
qoDIOYOK8NsoiUxk2UvPP4XpwfJyHYL1LuS3B85e3/RbVcfM2UIm/75CNb/yLJ09
1x4oLNBDkZQDhxwsT7VMg+h97eq/zJVhoAUXKN17JoV9hVmi5J46tskLAKhWA2vs
QuDd6pfxjc8TyaiMLNTDr7/72UNw/mn7zH9GedyhMRhyYnzy8qYOFa5k6/bFnV89
qRmKUqkaVDDf6dGtOOVvGP4iWj8TzrQsOa2qyj4UNUdj/9BSYHvodNPkOFMhUHqn
fUU6RUKUV3q1Uoj5E8HaMR7OHNMSx9OA7iWcpuMYAYbcyq4OJcE6ggy3FImrgTe0
9fBTw4Og3p91nBwOTajVj57wg5cs34YfBUQK+6P38A7+xTLBaVwvawaovAyVdDkD
y1Ae/WtloFz5aRzt8cNYfxvyzoFrGPRaomFgltLfLBhDELZcpXF8TQFpswN/wo4o
REFZdIWdiIYROykhX+FbKVMiufqj+snbpPACudio/DeC03Dj5oagDNJ5sfqiHn2m
93g2/twM3JT/bJOD01jL00yaSgaR4lWTelKbfrtqrgcZR1EryBwHv7VZykR066xJ
Private-MAC: 819054f7340f430ab9896ad76559cd2d489ab23bc517113e1cd425f461fac726`,
			keyType:  "ssh-rsa",
			password: []byte("testkey"),
			data:     rsa2048Key,
		},
	}
}

func Test_readHeader(t *testing.T) {
	header := "PuTTY-User-Key-File-2: ssh-rsa"
	expectedHeaderFormat := "PuTTY-User-Key-File-2"
	reader := strings.NewReader(header)
	h, err := readHeader(bufio.NewReader(reader))

	if err != nil {
		t.Errorf("got=[%s], expected=[%s]: %v", h, expectedHeaderFormat, err)
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
		t.Errorf("Failed to parse private key: %v", err)
		return
	}

	validateFields(t, key, mac2)

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
		t.Errorf("error loading Key fields: %v", err)
		return
	}
	validateFields(t, key, mac1)
}

func TestNew(t *testing.T) {
	key, err := New([]byte(keyContent))
	if err != nil {
		t.Errorf("error loading Key fields: %v", err)
		return
	}
	validateFields(t, key, mac1)
}

func validateFields(t *testing.T, key *Key, mac []byte) {
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

	if !bytes.Equal(key.PrivateMac, mac) {
		t.Errorf("got=[%s], expected=[%s]", hex.EncodeToString(key.PrivateMac), hex.EncodeToString(mac))
	}

	_, err := key.ParseRawPrivateKey(nil)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestParseRawPrivateKey(t *testing.T) {
	for i, fixture := range keysFixtures {
		key, err := New([]byte(fixture.content))
		if err != nil {
			t.Errorf("error loading key #%d: %v", i, err)
			continue
		}

		v, err := key.ParseRawPrivateKey(fixture.password)
		if err != nil {
			t.Errorf("error decrypting key #%d: %v", i, err)
			continue
		}

		switch v := v.(type) {
		case *dsa.PrivateKey, *rsa.PrivateKey, *ecdsa.PrivateKey, *ed25519.PrivateKey:
			if !reflect.DeepEqual(v, fixture.data) {
				fmt.Printf("Key: %#+v\nExpected %#+v\n", v, fixture.data)
				t.Errorf("error comparing a %T key with a %T key #%d", v, fixture.data, i)
			}
		default:
			t.Errorf("unknown %T key #%d type", v, i)
		}
	}
}

func TestParseRawPublicKey(t *testing.T) {
	for i, fixture := range keysFixtures {
		key, err := New([]byte(fixture.content))
		if err != nil {
			t.Errorf("error loading key #%d: %v", i, err)
			continue
		}

		v, err := key.ParseRawPublicKey()
		if err != nil {
			t.Errorf("error parsing public key #%d: %v", i, err)
			continue
		}

		switch v := v.(type) {
		case *dsa.PublicKey:
			if !reflect.DeepEqual(*v, fixture.data.(*dsa.PrivateKey).PublicKey) {
				t.Errorf("error verifying a %T key #%d", v, i)
			}
		case *rsa.PublicKey:
			if !reflect.DeepEqual(*v, fixture.data.(*rsa.PrivateKey).PublicKey) {
				t.Errorf("error verifying a %T key #%d", v, i)
			}
		case *ecdsa.PublicKey:
			if !reflect.DeepEqual(*v, fixture.data.(*ecdsa.PrivateKey).PublicKey) {
				t.Errorf("error verifying a %T key #%d", v, i)
			}
		case *ed25519.PublicKey:
			x := ed25519.PublicKey([]byte(*fixture.data.(*ed25519.PrivateKey))[ed25519.PublicKeySize:])
			if !reflect.DeepEqual(*v, x) {
				t.Errorf("error verifying a %T key #%d", v, i)
			}
		default:
			t.Errorf("unknown %T key #%d type", v, i)
		}
	}
}

func TestLoadFromUrandom(t *testing.T) {
	_, err := NewFromFile("/dev/urandom")
	if err == nil {
		t.Errorf("reading from /dev/urandom must return an error")
	}
	t.Logf("%v", err)
}
