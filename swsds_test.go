package swsds

import "testing"

var csp Crypto

func init() {
	csp = NewSwcsp()
	csp.OpenDevice()
}

/*func Test_DeviceAndSession(t *testing.T) {
	hSess, _ := csp.OpenSession()
	defer csp.CloseSession(hSess)
}

func Test_SM2_GenKeyPair(t *testing.T) {
	hSess, _ := csp.OpenSession()
	defer csp.CloseSession(hSess)

	_, err := csp.SM2_GenKeyPair(hSess)
	if err != nil {
		t.Error("GenKeyPair fail")
	}
}

func Test_SM2_SignAndVerify(t *testing.T) {
	hSess, _ := csp.OpenSession()
	defer csp.CloseSession(hSess)

	priKey, err := csp.SM2_GenKeyPair(hSess)
	if err != nil {
		t.Error("GenKeyPair fail")
	}
	//test the priKey by Sign_Verify
	msg := []byte("sansec")
	r, s, err := csp.SM2_Sign(hSess, priKey, msg)
	if err != nil {
		t.Error("Sign err")
	}
	ok, _ := csp.SM2_Verify(hSess, &priKey.PublicKey, msg, r, s)
	if !ok {
		t.Error("Verify fail")
	}
}

func Test_SM3_Hash(t *testing.T) {
	var msg []byte = []byte("sansec")

	hSess, _ := csp.OpenSession()
	defer csp.CloseSession(hSess)

	res1, _ := csp.SM3_Hash(hSess, msg)

	csp.SM3_HashInit(hSess)
	csp.SM3_HashUpdate(hSess, msg)
	res2, _ := csp.SM3_HashFinal(hSess)

	if len(res1) != len(res2) {
		t.Error("wrong length")
	}

	for i := 0; i < len(res1) && i < len(res2); i++ {
		if res1[i] != res2[i] {
			t.Error("hash err")
		}
	}
}

func Test_SM3_hmac(t *testing.T) {
	hSess, _ := csp.OpenSession()
	defer csp.CloseSession(hSess)
	var key []byte = []byte("key")
	var msg1 []byte = []byte("sansec")
	var msg2 []byte = []byte("swsds")

	hmac1, _ := csp.SM3_hmac(hSess, key, msg1)
	hmac2, _ := csp.SM3_hmac(hSess, key, msg2)
	if len(hmac1) != len(hmac2) {
		t.Error("hmac length err")
	}
	var same bool = true
	for i := 0; i < len(hmac1); i++ {
		if hmac1[i] != hmac2[i] {
			same = false
		}
	}
	if same {
		t.Error("hmac err")
	}
}

func Test_SM2_MultAdd(t *testing.T) {
	hSess, _ := csp.OpenSession()
	defer csp.CloseSession(hSess)

	var err error
	ePri, err := csp.SM2_GenKeyPair(hSess)
	aPri, err := csp.SM2_GenKeyPair(hSess)
	bPri, err := csp.SM2_GenKeyPair(hSess)

	aPub := aPri.PublicKey
	bPub := bPri.PublicKey

	cPub, err := csp.SM2_MultAdd(hSess, ePri, &aPub, &bPub)
	if err != nil {
		t.Error("MultAdd fail")
	}
	_ = cPub
}
func Benchmark_SM2_ModMultAdd(b *testing.B) {
	hSess, _ := csp.OpenSession()
	defer csp.CloseSession(hSess)
		aPri, err := csp.SM2_GenKeyPair(hSess)
		if err != nil {
			b.Error(err)
		}
		bPri, err := csp.SM2_GenKeyPair(hSess)
		if err != nil {
			b.Error(err)
		}
		cPri, err := csp.SM2_ModMultAdd(hSess, aPri, bPri)
		if err != nil {
			b.Error(err)
		}
		_ = cPri
	}
}

*/
func Test_SM2_ModMultAdd(t *testing.T) {
	hSess, _ := csp.OpenSession()
	defer csp.CloseSession(hSess)

	var err error
	aPri, err := csp.SM2_GenKeyPair(hSess)
	if err != nil {
		t.Error(err)
	}
	t.Log("aPri.D", aPri.D)
	bPri, err := csp.SM2_GenKeyPair(hSess)
	if err != nil {
		t.Error(err)
	}
	t.Log("bPri.D", bPri.D)

	/*
		aPri, bPri := new(ecdsa.PrivateKey), new(ecdsa.PrivateKey)
		aPri.D, _ = new(big.Int).SetString("0717300514688552599685228064015849944438029799700315748216576065320982", 10)
		bPri.D, _ = new(big.Int).SetString("15891397270839149416983174565732741266443072436586274829147058492915", 10)

	*/
	cPri, err := csp.SM2_ModMultAdd(hSess, aPri, bPri)
	if err != nil {
		t.Error(err)
	}

	_ = cPri
}

/*
func Test_SM4_crypt_EncAndDec(t *testing.T) {
	key := []byte("1234567812345678")
	msg := []byte("sansec")
	cpr, _ := csp.SM4_crypt_enc(key, msg)
	if cpr == nil {
		t.Error("SM4_crypt_enc fail")
	}
	pln, _ := csp.SM4_crypt_dec(key, cpr)

	if len(msg) != len(pln) {
		fmt.Println("msg", msg)
		fmt.Println("pln", pln)

		t.Error("SM4_crypt_dec fail")
	}

	for i := 0; i < len(msg); i++ {
		if msg[i] != pln[i] {
			t.Error("Can't decrypt, error")
		}
	}
}
*/
func Test_Close(t *testing.T) {
	csp.CloseDevice()
}

/*
msg:  hello world, hello world
hash:  [195 67 246 122 52 35 150 30 157 147 203 31 13 106 170 112 64 231 199 218 191 102 189 69 92 108 65 127 153 250 104 42]
D:  23975483598876884298529059711121659238225508025131081770608950953671194982528502537563870996636402457202068344087032
X:  36867246183724785534670931138273922488717281608782831811305615183801315860173673093595414044290690635411499643182489
Y:  3579336333986994787125356962138736758359030708665150999359108283664854301272477348861368004805555546749552833445695
r:  21779111779685509038872927360013300214564093712045271632247014149709540297545159959367291323906847926743829456856698
s:  7696660709777259717489567807873733678903414136728780938898212388762710735375873038673985898514281428606944926001041
Verify Result:  true
*/
/*
=== RUN   Test_SM2_ModMultAdd
aPrk {256 [243 122 172 225 31 95 254 223 111 208 158 29 22 105 235 203 200 250 108 253 229 193 58 9 30 72 36 231 251 250 184 22]}
bPrk {256 [3 172 123 13 92 75 105 209 177 216 48 178 128 199 147 8 12 16 109 231 18 28 131 9 205 41 231 182 199 192 85 243]}
cPrk {0 [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]}
--- PASS: Test_SM2_ModMultAdd (0.01s)
	swsds_test.go:140: aPri.D 110128770717300514688552599685228064015849944438029799700315748216576065320982
	swsds_test.go:145: bPri.D 1661685515891397270839149416983174565732741266443072436586274829147058492915
=== RUN   Test_Close
--- PASS: Test_Close (0.00s)
PASS
ok  	github.com/warm3snow/swsds	0.105s
*/
