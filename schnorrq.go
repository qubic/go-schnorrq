package go_schnorrq

import (
	"github.com/cloudflare/circl/ecc/fourq"
	"github.com/cloudflare/circl/xof/k12"
	"github.com/pkg/errors"
)

func Sign(subSeed [32]byte, pubKey [32]byte, messageDigest [32]byte) ([64]byte, error) {

	//Get sub-seed hash
	subSeedHash, err := K12Hash64(subSeed[:])
	if err != nil {
		return [64]byte{}, errors.Wrap(err, "Hashing sub-seed.")
	}

	//Initialize temp and fill last 2/3 32-byte parts with the sub subseed hash and message
	var temp [96]byte
	copy(temp[32:], subSeedHash[32:])
	copy(temp[64:], messageDigest[:])

	//Create scalar for point multiplication by hashing last 2/3 32-byte parts of temp

	slice := temp[32:]

	scalar64, err := K12Hash64(slice)
	if err != nil {
		return [64]byte{}, errors.Wrap(err, "Creating scalar.")
	}

	//Initialize point
	var point fourq.Point

	//Use first 32 bytes of scalar for multiplication - Will have to check if this is correct
	var scalar32 [32]byte
	copy(scalar32[:], scalar64[:32]) // TODO: verify that this is accurate

	//Perform fixed-base multiplication
	point.ScalarBaseMult(&scalar32)

	//Get 32-byte array point encoding.
	var pointEncoding [32]byte

	point.Marshal(&pointEncoding)

	//Fill first 1/3 32-byte part of temp with point encoding.
	copy(temp[:32], pointEncoding[:])

	//Fill 2/3 32-byte part of temp with public key
	copy(temp[32:], pubKey[:])

	finalHash, err := K12Hash64(temp[:])
	if err != nil {
		return [64]byte{}, errors.Wrap(err, "Final hash.")
	}

	//scalar64 = scalar64 * Rprime

	//scalar64BI := new(big.Int).SetBytes(scalar64[:])

	//scalar64BI = multiply(scalar64BI, M_RP)

	return finalHash, nil
	//TODO: montgomery stuff

}

func Verify(pubKey [32]byte, messageDigest [32]byte, signature [64]byte) error {

	if (pubKey[15]&0x80 != 0) || (signature[15]&0x80 != 0) || (signature[62]&0xC0 != 0) || signature[63] != 0 {
		return errors.New("Bad public key.")
	}

	//Initialize point
	var point fourq.Point

	//Initialize temp
	var temp [96]byte

	//Decode public key
	if !point.Unmarshal(&pubKey) {
		return errors.New("Failed to decode public key.")
	}

	copy(temp[:32], signature[:32])
	copy(temp[32:], pubKey[:])
	copy(temp[64:], messageDigest[:])

	tempHash, err := K12Hash64(temp[:])
	if err != nil {
		return errors.Wrap(err, "Failed to hash temp while verifying signature.")
	}

	signatureSlice := [32]byte{}
	copy(signatureSlice[:], signature[32:])

	tempHashSlice := [32]byte{}
	copy(tempHashSlice[:], tempHash[:32])

	point.DoubleScalarMult(&signatureSlice, &point, &tempHashSlice)

	encoded := [32]byte{}

	point.Marshal(&encoded)

	copy(signatureSlice[:], signature[:32])

	if encoded != signatureSlice {
		return errors.New("Signature does not verify!")
	}
	return nil

}

func K12Hash64(data []byte) ([64]byte, error) {

	h := k12.NewDraft10([]byte{}) // Using K12 for hashing, equivalent to KangarooTwelve(temp, 96, h, 64).
	_, err := h.Write(data)
	if err != nil {
		return [64]byte{}, errors.Wrap(err, "k12 hashing")
	}
	var out = [64]byte{}
	_, err = h.Read(out[:])
	if err != nil {
		return [64]byte{}, errors.Wrap(err, "reading k12 digest")
	}
	return out, nil
}
