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

	data := []struct {
		name        string
		publicKey   [32]byte
		message     [32]byte
		signature   [64]byte
		expectError bool
	}{
		{
			name: "TestVerify_1",
			publicKey: [32]byte{
				0x1f, 0x59, 0x0d, 0x03, 0xe6, 0x13, 0xbd, 0xde,
				0xd3, 0x8b, 0x4c, 0x08, 0x20, 0xac, 0x44, 0x61,
				0x5f, 0x91, 0xaf, 0x12, 0x43, 0x59, 0x80, 0xb3,
				0xed, 0xe3, 0xc0, 0x8c, 0x31, 0x5a, 0x25, 0x44,
			},
			message: [32]byte{
				0xa6, 0x82, 0x8f, 0xcb, 0x9b, 0x68, 0x6f, 0x08,
				0x74, 0x08, 0x57, 0x2b, 0xf3, 0x16, 0xe8, 0x9b,
				0x2d, 0x96, 0xfc, 0x48, 0x11, 0xb5, 0xd0, 0x75,
				0x4b, 0xfd, 0xbd, 0x5b, 0x8a, 0xd7, 0x76, 0x0d,
			},
			signature: [64]byte{
				0x60, 0xce, 0xd0, 0x82, 0xa0, 0x31, 0xb8, 0x97,
				0x3c, 0x8b, 0x77, 0xe3, 0x9b, 0x07, 0x8c, 0x1e,
				0xd5, 0x1b, 0xac, 0xf5, 0x95, 0x03, 0xfd, 0x19,
				0xe8, 0x6c, 0x34, 0x0e, 0xc9, 0x0c, 0x85, 0xa7,
				0x37, 0x27, 0x53, 0xc3, 0x63, 0x4c, 0xcc, 0x88,
				0xcc, 0xfa, 0x9f, 0xd0, 0x17, 0xa8, 0x60, 0x59,
				0x02, 0xde, 0x96, 0xab, 0x0d, 0xba, 0x73, 0x24,
				0x01, 0x6a, 0xfe, 0x54, 0x52, 0x22, 0x11, 0x00,
			},
			expectError: false,
		},
		{
			name: "TestVerify_2",
			publicKey: [32]byte{
				0x9e, 0x1a, 0x10, 0x0c, 0xfb, 0x55, 0x6d, 0xef,
				0x7b, 0xcc, 0x62, 0x52, 0xe4, 0x7d, 0xdf, 0x09,
				0x85, 0x42, 0x86, 0x37, 0xc3, 0xd1, 0xb3, 0xca,
				0xa1, 0x6f, 0x33, 0xfd, 0x98, 0x43, 0x8d, 0x94,
			},
			message: [32]byte{
				0x8a, 0x48, 0x1c, 0x7a, 0xe4, 0xa7, 0xc3, 0x3c,
				0xa9, 0xa5, 0x1d, 0x64, 0xcf, 0xa1, 0x13, 0xe5,
				0x10, 0xc2, 0xf7, 0x8f, 0xf5, 0x8d, 0x8b, 0xd4,
				0x13, 0xfb, 0x6f, 0x49, 0x21, 0xab, 0xce, 0xb7,
			},
			signature: [64]byte{
				0xb2, 0x36, 0xe4, 0xe6, 0x0a, 0x1d, 0x75, 0x94,
				0x5a, 0x3a, 0xa8, 0x25, 0x95, 0x14, 0xa5, 0x4e,
				0x0b, 0x16, 0xac, 0x4b, 0xaa, 0x4e, 0x46, 0x6a,
				0x91, 0x39, 0x53, 0xc3, 0xde, 0xb7, 0xb5, 0x36,
				0x6b, 0xf2, 0x2f, 0xe3, 0x50, 0xcb, 0x88, 0x22,
				0xed, 0xa2, 0xfd, 0x16, 0x04, 0xf9, 0x06, 0x2c,
				0xf2, 0x16, 0xdb, 0xb4, 0x0f, 0x88, 0xec, 0x34,
				0x17, 0x88, 0x63, 0x89, 0x68, 0xe3, 0x13, 0x00,
			},
			expectError: false,
		},
		{
			name: "TestVerify_3",
			publicKey: [32]byte{
				0x76, 0x3a, 0x77, 0x83, 0x33, 0x7b, 0xd6, 0x2b,
				0x6e, 0xb5, 0x76, 0x30, 0x57, 0x52, 0x2d, 0x40,
				0xce, 0x51, 0x2f, 0x0a, 0xe1, 0x02, 0x58, 0x2f,
				0x1a, 0xae, 0x15, 0x53, 0x0b, 0xe8, 0x2c, 0x35,
			},
			message: [32]byte{
				0x8a, 0x48, 0x1c, 0x7a, 0xe4, 0xa7, 0xc3, 0x3c,
				0xa9, 0xa5, 0x1d, 0x64, 0xcf, 0xa1, 0x13, 0xe5,
				0x10, 0xc2, 0xf7, 0x8f, 0xf5, 0x8d, 0x8b, 0xd4,
				0x13, 0xfb, 0x6f, 0x49, 0x21, 0xab, 0xce, 0xb7,
			},
			signature: [64]byte{
				0xe3, 0xf8, 0xc3, 0xb7, 0x01, 0x17, 0x8e, 0xf1,
				0xe7, 0x14, 0xbe, 0x3f, 0x30, 0x54, 0xe4, 0x21,
				0x10, 0xd0, 0x18, 0xde, 0x98, 0x9a, 0x2e, 0xc6,
				0xea, 0x05, 0xad, 0x44, 0x7b, 0xda, 0x5a, 0xae,
				0x93, 0x77, 0xd0, 0x8d, 0x28, 0x02, 0xc4, 0x44,
				0x2a, 0xae, 0xb7, 0x3a, 0x83, 0xd8, 0x62, 0x6e,
				0x0f, 0xda, 0x75, 0x1c, 0xe2, 0xcc, 0x86, 0xfa,
				0x27, 0xde, 0x45, 0x91, 0x39, 0x54, 0x27, 0x00,
			},
			expectError: false,
		},
		{
			name: "TestVerify_4_PublicKeyValidity",
			publicKey: [32]byte{
				0x1f, 0x59, 0x0d, 0x03, 0xe6, 0x13, 0xbd, 0xde,
				0xd3, 0x8b, 0x4c, 0x08, 0x20, 0xac, 0x44, 0x81,
				0x5f, 0x91, 0xaf, 0x12, 0x43, 0x59, 0x80, 0xb3,
				0xed, 0xe3, 0xc0, 0x8c, 0x31, 0x5a, 0x25, 0x44,
			},
			message: [32]byte{
				0xa6, 0x82, 0x8f, 0xcb, 0x9b, 0x68, 0x6f, 0x08,
				0x74, 0x08, 0x57, 0x2b, 0xf3, 0x16, 0xe8, 0x9b,
				0x2d, 0x96, 0xfc, 0x48, 0x11, 0xb5, 0xd0, 0x75,
				0x4b, 0xfd, 0xbd, 0x5b, 0x8a, 0xd7, 0x76, 0x0d,
			},
			signature: [64]byte{
				0x60, 0xce, 0xd0, 0x82, 0xa0, 0x31, 0xb8, 0x97,
				0x3c, 0x8b, 0x77, 0xe3, 0x9b, 0x07, 0x8c, 0x1e,
				0xd5, 0x1b, 0xac, 0xf5, 0x95, 0x03, 0xfd, 0x19,
				0xe8, 0x6c, 0x34, 0x0e, 0xc9, 0x0c, 0x85, 0xa7,
				0x37, 0x27, 0x53, 0xc3, 0x63, 0x4c, 0xcc, 0x88,
				0xcc, 0xfa, 0x9f, 0xd0, 0x17, 0xa8, 0x60, 0x59,
				0x02, 0xde, 0x96, 0xab, 0x0d, 0xba, 0x73, 0x24,
				0x01, 0x6a, 0xfe, 0x54, 0x52, 0x22, 0x11, 0x00,
			},
			expectError: true,
		},
		{
			name: "TestVerify_5_SignatureValidity_1",
			publicKey: [32]byte{
				0x1f, 0x59, 0x0d, 0x03, 0xe6, 0x13, 0xbd, 0xde,
				0xd3, 0x8b, 0x4c, 0x08, 0x20, 0xac, 0x44, 0x61,
				0x5f, 0x91, 0xaf, 0x12, 0x43, 0x59, 0x80, 0xb3,
				0xed, 0xe3, 0xc0, 0x8c, 0x31, 0x5a, 0x25, 0x44,
			},
			message: [32]byte{
				0xa6, 0x82, 0x8f, 0xcb, 0x9b, 0x68, 0x6f, 0x08,
				0x74, 0x08, 0x57, 0x2b, 0xf3, 0x16, 0xe8, 0x9b,
				0x2d, 0x96, 0xfc, 0x48, 0x11, 0xb5, 0xd0, 0x75,
				0x4b, 0xfd, 0xbd, 0x5b, 0x8a, 0xd7, 0x76, 0x0d,
			},
			signature: [64]byte{
				0x60, 0xce, 0xd0, 0x82, 0xa0, 0x31, 0xb8, 0x97,
				0x3c, 0x8b, 0x77, 0xe3, 0x9b, 0x07, 0x8c, 0x81,
				0xd5, 0x1b, 0xac, 0xf5, 0x95, 0x03, 0xfd, 0x19,
				0xe8, 0x6c, 0x34, 0x0e, 0xc9, 0x0c, 0x85, 0xa7,
				0x37, 0x27, 0x53, 0xc3, 0x63, 0x4c, 0xcc, 0x88,
				0xcc, 0xfa, 0x9f, 0xd0, 0x17, 0xa8, 0x60, 0x59,
				0x02, 0xde, 0x96, 0xab, 0x0d, 0xba, 0x73, 0x24,
				0x01, 0x6a, 0xfe, 0x54, 0x52, 0x22, 0x11, 0x00,
			},
			expectError: true,
		},
		{
			name: "TestVerify_6_SignatureValidity_2",
			publicKey: [32]byte{
				0x1f, 0x59, 0x0d, 0x03, 0xe6, 0x13, 0xbd, 0xde,
				0xd3, 0x8b, 0x4c, 0x08, 0x20, 0xac, 0x44, 0x61,
				0x5f, 0x91, 0xaf, 0x12, 0x43, 0x59, 0x80, 0xb3,
				0xed, 0xe3, 0xc0, 0x8c, 0x31, 0x5a, 0x25, 0x44,
			},
			message: [32]byte{
				0xa6, 0x82, 0x8f, 0xcb, 0x9b, 0x68, 0x6f, 0x08,
				0x74, 0x08, 0x57, 0x2b, 0xf3, 0x16, 0xe8, 0x9b,
				0x2d, 0x96, 0xfc, 0x48, 0x11, 0xb5, 0xd0, 0x75,
				0x4b, 0xfd, 0xbd, 0x5b, 0x8a, 0xd7, 0x76, 0x0d,
			},
			signature: [64]byte{
				0x60, 0xce, 0xd0, 0x82, 0xa0, 0x31, 0xb8, 0x97,
				0x3c, 0x8b, 0x77, 0xe3, 0x9b, 0x07, 0x8c, 0x1e,
				0xd5, 0x1b, 0xac, 0xf5, 0x95, 0x03, 0xfd, 0x19,
				0xe8, 0x6c, 0x34, 0x0e, 0xc9, 0x0c, 0x85, 0xa7,
				0x37, 0x27, 0x53, 0xc3, 0x63, 0x4c, 0xcc, 0x88,
				0xcc, 0xfa, 0x9f, 0xd0, 0x17, 0xa8, 0x60, 0x59,
				0x02, 0xde, 0x96, 0xab, 0x0d, 0xba, 0x73, 0x24,
				0x01, 0x6a, 0xfe, 0x54, 0x52, 0x22, 0x11, 0x01,
			},
			expectError: true,
		},
	}

	for _, testData := range data {
		t.Run(testData.name, func(t *testing.T) {

			err := Verify(testData.publicKey, testData.message, testData.signature)

			//If we get an error
			if err != nil {
				//If error is expected
				if testData.expectError {
					t.Logf("Got expected error: %s\n", err.Error())
					//Return, all is good
					return
				}

				t.Fatalf("Signature verification failure: %s\n", err.Error())
				//Return as FailNow() does not halt execution.
				return

			}

			//If we expect an error but don't get any
			if testData.expectError {
				t.Fatalf("Error expected but got none!")
			}
		})
	}

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
