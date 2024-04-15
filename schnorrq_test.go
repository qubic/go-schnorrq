package schnorrq

import (
	"bytes"
	"encoding/hex"
	"github.com/cloudflare/circl/ecc/fourq"
	"os/exec"
	"testing"
)

func getPublicKey(sk [32]byte) ([32]byte, error) {
	var p fourq.Point

	p.ScalarBaseMult(&sk)

	pubKey := [32]byte{}
	p.Marshal(&pubKey)
	return pubKey, nil
}

var (
	signature = [64]byte{
		0x60, 0xce, 0xd0, 0x82, 0xa0, 0x31, 0xb8, 0x97,
		0x3c, 0x8b, 0x77, 0xe3, 0x9b, 0x07, 0x8c, 0x1e,
		0xd5, 0x1b, 0xac, 0xf5, 0x95, 0x03, 0xfd, 0x19,
		0xe8, 0x6c, 0x34, 0x0e, 0xc9, 0x0c, 0x85, 0xa7,
		0x37, 0x27, 0x53, 0xc3, 0x63, 0x4c, 0xcc, 0x88,
		0xcc, 0xfa, 0x9f, 0xd0, 0x17, 0xa8, 0x60, 0x59,
		0x02, 0xde, 0x96, 0xab, 0x0d, 0xba, 0x73, 0x24,
		0x01, 0x6a, 0xfe, 0x54, 0x52, 0x22, 0x11, 0x00,
	}
	message = [32]byte{
		0xa6, 0x82, 0x8f, 0xcb, 0x9b, 0x68, 0x6f, 0x08,
		0x74, 0x08, 0x57, 0x2b, 0xf3, 0x16, 0xe8, 0x9b,
		0x2d, 0x96, 0xfc, 0x48, 0x11, 0xb5, 0xd0, 0x75,
		0x4b, 0xfd, 0xbd, 0x5b, 0x8a, 0xd7, 0x76, 0x0d,
	}
	privateKey = [32]byte{
		0x62, 0x50, 0x6d, 0x37, 0x0a, 0x4e, 0x9f, 0x42,
		0x72, 0x02, 0x69, 0xc0, 0xc9, 0x73, 0xa5, 0x44,
		0xde, 0x0b, 0x65, 0x59, 0xbd, 0xa4, 0x6d, 0x1d,
		0x8d, 0xd2, 0xfc, 0xda, 0x9f, 0xe4, 0xfa, 0xda,
	}
	publicKey, _ = getPublicKey(privateKey)

	//For program benchmark:

	publicKeyString = hex.EncodeToString(publicKey[:])
	messageString   = hex.EncodeToString(message[:])
	signatureString = hex.EncodeToString(signature[:])
)

/*func TestSign(t *testing.T) {

	expectedSignature := [64]byte{
		0x60, 0xce, 0xd0, 0x82, 0xa0, 0x31, 0xb8, 0x97,
		0x3c, 0x8b, 0x77, 0xe3, 0x9b, 0x07, 0x8c, 0x1e,
		0xd5, 0x1b, 0xac, 0xf5, 0x95, 0x03, 0xfd, 0x19,
		0xe8, 0x6c, 0x34, 0x0e, 0xc9, 0x0c, 0x85, 0xa7,
		0x37, 0x27, 0x53, 0xc3, 0x63, 0x4c, 0xcc, 0x88,
		0xcc, 0xfa, 0x9f, 0xd0, 0x17, 0xa8, 0x60, 0x59,
		0x02, 0xde, 0x96, 0xab, 0x0d, 0xba, 0x73, 0x24,
		0x01, 0x6a, 0xfe, 0x54, 0x52, 0x22, 0x11, 0x00,
	}

	message := [32]byte{
		0xa6, 0x82, 0x8f, 0xcb, 0x9b, 0x68, 0x6f, 0x08,
		0x74, 0x08, 0x57, 0x2b, 0xf3, 0x16, 0xe8, 0x9b,
		0x2d, 0x96, 0xfc, 0x48, 0x11, 0xb5, 0xd0, 0x75,
		0x4b, 0xfd, 0xbd, 0x5b, 0x8a, 0xd7, 0x76, 0x0d,
	}

	privateKey := [32]byte{
		0x62, 0x50, 0x6d, 0x37, 0x0a, 0x4e, 0x9f, 0x42,
		0x72, 0x02, 0x69, 0xc0, 0xc9, 0x73, 0xa5, 0x44,
		0xde, 0x0b, 0x65, 0x59, 0xbd, 0xa4, 0x6d, 0x1d,
		0x8d, 0xd2, 0xfc, 0xda, 0x9f, 0xe4, 0xfa, 0xda,
	}

	subSeed := [32]byte{
		0x44, 0x53, 0x51, 0x2f, 0x1e, 0xf5, 0x97, 0xb3,
		0x65, 0xcc, 0x38, 0x4f, 0x0a, 0x2b, 0x10, 0xce,
		0xb5, 0xc9, 0x4f, 0x51, 0x6b, 0x91, 0x1a, 0xcc,
		0x8e, 0x8b, 0xc1, 0xb5, 0x5e, 0x64, 0x6c, 0x74,
	}

	publicKey, _ := getPublicKey(privateKey)

	sgn, _ := Sign(subSeed, publicKey, message)

	fmt.Printf("signature: %s\n", hex.EncodeToString(sgn[:]))

	if cmp.Diff(sgn, expectedSignature) != "" {
		t.Fatalf("Signature test failure! \nExpected: %s \nGot: 	  %s", hex.EncodeToString(expectedSignature[:]), hex.EncodeToString(sgn[:]))
	}

}*/

func TestVerify(t *testing.T) {

	signature := [64]byte{
		0x60, 0xce, 0xd0, 0x82, 0xa0, 0x31, 0xb8, 0x97,
		0x3c, 0x8b, 0x77, 0xe3, 0x9b, 0x07, 0x8c, 0x1e,
		0xd5, 0x1b, 0xac, 0xf5, 0x95, 0x03, 0xfd, 0x19,
		0xe8, 0x6c, 0x34, 0x0e, 0xc9, 0x0c, 0x85, 0xa7,
		0x37, 0x27, 0x53, 0xc3, 0x63, 0x4c, 0xcc, 0x88,
		0xcc, 0xfa, 0x9f, 0xd0, 0x17, 0xa8, 0x60, 0x59,
		0x02, 0xde, 0x96, 0xab, 0x0d, 0xba, 0x73, 0x24,
		0x01, 0x6a, 0xfe, 0x54, 0x52, 0x22, 0x11, 0x00,
	}

	message := [32]byte{
		0xa6, 0x82, 0x8f, 0xcb, 0x9b, 0x68, 0x6f, 0x08,
		0x74, 0x08, 0x57, 0x2b, 0xf3, 0x16, 0xe8, 0x9b,
		0x2d, 0x96, 0xfc, 0x48, 0x11, 0xb5, 0xd0, 0x75,
		0x4b, 0xfd, 0xbd, 0x5b, 0x8a, 0xd7, 0x76, 0x0d,
	}

	privateKey := [32]byte{
		0x62, 0x50, 0x6d, 0x37, 0x0a, 0x4e, 0x9f, 0x42,
		0x72, 0x02, 0x69, 0xc0, 0xc9, 0x73, 0xa5, 0x44,
		0xde, 0x0b, 0x65, 0x59, 0xbd, 0xa4, 0x6d, 0x1d,
		0x8d, 0xd2, 0xfc, 0xda, 0x9f, 0xe4, 0xfa, 0xda,
	}

	publicKey, _ := getPublicKey(privateKey)

	//Test with valid data.
	err := Verify(publicKey, message, signature)
	if err != nil {
		t.Fatalf("Signature verification failure: %s\n", err.Error())
	}
	err = nil

	//Test with invalid data

	//Input validity

	//Public key:
	byte15 := publicKey[15]
	publicKey[15] += 0x80
	err = Verify(publicKey, message, signature)
	if err == nil {
		t.Fatal("Failed to check public key validity.")
	}
	publicKey[15] = byte15
	err = nil

	//Signature:
	byte15 = signature[15]
	signature[15] += 0x80
	err = Verify(publicKey, message, signature)
	if err == nil {
		t.Fatalf("Failed to check signature validity.")
	}
	signature[15] = byte15
	err = nil

	signature[63] = 1
	err = Verify(publicKey, message, signature)
	if err == nil {
		t.Fatalf("Failed to check signature validity.")
	}
	signature[63] = 0
	err = nil

	//Check for general bad data

	//Check against bad public key
	publicKey[0] += 1
	err = Verify(publicKey, message, signature)
	if err == nil {
		t.Fatalf("Signature was verified with bad public key!")
	}
	publicKey[0] -= 1
	err = nil

	//Check against bad signature
	signature[1] += 2
	err = Verify(publicKey, message, signature)
	if err == nil {
		t.Fatalf("Signature was verified with bad signature!")
	}
	signature[1] -= 2
	err = nil

	//Check against bad message
	message[2] += 3
	err = Verify(publicKey, message, signature)
	if err == nil {
		t.Fatalf("Signature was verified with bad message!")
	}
	message[2] -= 3
	err = nil
}

func BenchmarkVerify(b *testing.B) {

	for i := 0; i < b.N; i++ {
		err := Verify(publicKey, message, signature)
		if err != nil {
			b.Fatalf("Failed to verify good data.")
		}
	}
}

func BenchmarkVerifyProgram(b *testing.B) {

	for i := 0; i < b.N; i++ {
		cmd := exec.Command("./fourq_verify", publicKeyString, messageString, signatureString)
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			b.Fatalf("Program cannot verify good data.")
		}

	}

}
