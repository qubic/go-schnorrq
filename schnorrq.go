package schnorrq

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/linckode/circl/ecc/fourq"
	"github.com/linckode/circl/xof/k12"
)

// curveOrder is the FourQ subgroup order r as four little-endian uint64 limbs
// (limb 0 = least significant). Mirrors order.qElement (see order/element.go:55-68)
// and CURVE_ORDER_{0..3} in qubic/core src/four_q.h.
var curveOrder = [4]uint64{
	3436901888089820391,
	16122042576031152537,
	17317351579400803557,
	11764505149049458,
}

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

	if (pubKey[15]&0x80 != 0) || (signature[15]&0x80 != 0) {
		return errors.New("Bad public key or signature.")
	}

	// Reject non-canonical scalars (s >= curve_order). Without this, a twin
	// s' = s + r is also a valid signature on the same payload, producing a
	// different tx hash and enabling replay/double-execution. Matches the
	// canonical-S check added in qubic/core commit 05f7348.
	var s [4]uint64
	for i := 0; i < 4; i++ {
		s[i] = binary.LittleEndian.Uint64(signature[32+i*8:])
	}
	canonical := false
	for i := 3; i >= 0; i-- {
		if s[i] < curveOrder[i] {
			canonical = true
			break
		}
		if s[i] > curveOrder[i] {
			break
		}
	}
	if !canonical {
		return errors.New("Non-canonical signature scalar.")
	}

	// Fast-path reject of the identity (neutral) point, encoded as 01 00..00. It is the
	// most dangerous forgeable key: a single forged (R,S) is valid for EVERY message, with
	// no grinding and no private key. Mask the sign bit of the top limb, matching decode().
	var pk [4]uint64
	for i := 0; i < 4; i++ {
		pk[i] = binary.LittleEndian.Uint64(pubKey[i*8:])
	}
	if pk[1] == 0 && pk[2] == 0 && (pk[3]&0x7FFFFFFFFFFFFFFF) == 0 {
		return errors.New("Malformed public key.")
	}

	//Initialize point
	var point fourq.Point

	//Initialize temp
	var temp [96]byte

	//Decode public key
	if !point.Unmarshal(&pubKey) {
		return errors.New("Failed to decode public key.")
	}

	// Reject low-order (weak) public keys to prevent signature forgery.
	// FourQ's group order is 392*r (cofactor 392 = 2^3 * 7^2, r = prime subgroup order).
	// Any key whose order divides 392 (the 392-point cofactor subgroup, including the
	// identity, NULL_ID, and the non-canonical y=p alias) lets an attacker forge a valid
	// signature without a private key, because h*A then depends only on h mod (order of A).
	// A legitimate key has order r, so [392]*A != O; every weak key has [392]*A == O.
	// cofactor_clearing() computes exactly [392]*A. The neutral point is the only possible
	// weak result and has affine x = 0, i.e. projective X == 0 (Z is never 0 here), so we
	// test the reduced projective X directly and avoid eccnorm's field inversion.
	if point.IsWeak() {
		return errors.New("Weak (low-order) public key.")
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
