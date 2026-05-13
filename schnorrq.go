package schnorrq

import (
	"errors"
	"fmt"

	"github.com/linckode/circl/ecc/fourq"
	"github.com/linckode/circl/xof/k12"
)

func Sign(subSeed [32]byte, pubKey [32]byte, messageDigest [32]byte) ([64]byte, error) {

	//Get sub-seed hash
	subSeedHash, err := K12Hash64(subSeed[:])
	if err != nil {
		return [64]byte{}, fmt.Errorf("hashing sub-seed: %w", err)
	}

	//Initialize temp and fill last 2/3 32-byte parts with the sub sub-seed hash and message
	var temp [96]byte
	copy(temp[32:], subSeedHash[32:])
	copy(temp[64:], messageDigest[:])

	//Create scalar for point multiplication by hashing last 2/3 32-byte parts of temp
	tempHash, err := K12Hash64(temp[32:])
	if err != nil {
		return [64]byte{}, fmt.Errorf("hashing last 2/3 parts of temp slice: %w", err)
	}

	//Initialize point
	var point fourq.Point

	//Use first 32 bytes of tempHash as scalar for multiplication
	var scalar [32]byte
	copy(scalar[:], tempHash[:32])

	//Perform fixed-base multiplication
	point.ScalarBaseMult(&scalar)

	//Get 32-byte array point encoding.
	var pointEncoding [32]byte
	point.Marshal(&pointEncoding)

	//Fill first 1/3 32-byte part of temp with point encoding.
	copy(temp[:32], pointEncoding[:])

	//Fill 2/3 32-byte part of temp with public key
	copy(temp[32:], pubKey[:])

	finalHash, err := K12Hash64(temp[:])
	if err != nil {
		return [64]byte{}, fmt.Errorf("hashing temp: %w", err)
	}

	//Normalize tempHash[0-31] and finalHash[0-31]
	var montgomeryTempHash MontgomeryNumber
	err = montgomeryTempHash.FromStandard(tempHash[:32], LittleEndian, true)
	if err != nil {
		return [64]byte{}, fmt.Errorf("tempHash mod order: %w", err)
	}

	var montgomeryFinalHash MontgomeryNumber
	err = montgomeryFinalHash.FromStandard(finalHash[:32], LittleEndian, true)
	if err != nil {
		return [64]byte{}, fmt.Errorf("finalHash mod order: %w", err)
	}

	//subSeedHash to Montgomery
	var montgomerySubSeedHash MontgomeryNumber
	err = montgomerySubSeedHash.FromStandard(subSeedHash[:32], LittleEndian, false)
	if err != nil {
		return [64]byte{}, fmt.Errorf("SubSeedHash mod order: %w", err)
	}

	//Perform multiplication
	montgomerySubSeedHash.Mult(montgomerySubSeedHash, montgomeryFinalHash)

	//Final subtraction
	montgomerySubSeedHash.Sub(montgomeryTempHash, montgomerySubSeedHash)

	//Assemble signature
	var signature [64]byte
	copy(signature[:32], pointEncoding[:])

	subSeedHashArray := montgomerySubSeedHash.ToStandard()

	copy(signature[32:], subSeedHashArray[:])

	return signature, nil
}

func Verify(pubKey [32]byte, messageDigest [32]byte, signature [64]byte) error {

	if (pubKey[15]&0x80 != 0) || (signature[15]&0x80 != 0) || (signature[62]&0xC0 != 0) || signature[63] != 0 {
		return errors.New("Bad public key or signature.")
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
		return fmt.Errorf("Failed to hash temp while verifying signature.: %w", err)
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
		return [64]byte{}, fmt.Errorf("k12 hashing: %w", err)
	}
	var out = [64]byte{}
	_, err = h.Read(out[:])
	if err != nil {
		return [64]byte{}, fmt.Errorf("reading k12 digest: %w", err)
	}
	return out, nil
}
