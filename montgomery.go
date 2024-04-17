package schnorrq

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
	"github.com/qubic/go-schnorrq/order"
	"math/big"
)

type Endianness bool

const (
	LittleEndian Endianness = false
	BigEndian    Endianness = true
)

type MontgomeryNumber struct {
	orderElement order.Element
	endianness   Endianness
}

func (number *MontgomeryNumber) FromStandard(array []byte, endian Endianness, doModOrder bool) error {

	if len(array) != 32 {
		return errors.New("cannot create Montgomery number, input array is not 32 bytes long")
	}

	var data [32]byte
	copy(data[:], array[:])

	//If we have to mod order the number first
	if doModOrder {
		data = modOrder(data, endian)
	}

	number.endianness = endian
	number.orderElement = elementFromStandard(data, endian)

	return nil
}

func (number *MontgomeryNumber) ToStandard() [32]byte {
	return elementToStandard(number.orderElement, number.endianness)
}

func (number *MontgomeryNumber) Mult(ma, mb MontgomeryNumber) {

	var element order.Element

	element.Mul(&ma.orderElement, &mb.orderElement)

	number.orderElement = element
	number.endianness = ma.endianness
}

func (number *MontgomeryNumber) Sub(ma, mb MontgomeryNumber) {

	var element order.Element

	element.Sub(&ma.orderElement, &mb.orderElement)

	number.orderElement = element
	number.endianness = ma.endianness
}

// Print prints the contents of the MontgomeryNumber
func (number *MontgomeryNumber) Print(standardRepresentation bool) {
	printElement(number.orderElement, standardRepresentation)
}

//Utility functions

func reverseEndianness(array []byte) []byte {

	length := len(array)
	reverse := make([]byte, length)

	for i := 0; i < length; i++ {
		reverse[i] = array[length-i-1]
	}
	return reverse
}

func modOrder(array [32]byte, endian Endianness) [32]byte {
	return elementToStandard(elementFromStandard(array, endian), endian)
}

//Element functions

func elementFromStandard(array [32]byte, endian Endianness) order.Element {
	var element order.Element

	switch endian {
	case BigEndian:
		element.SetBigInt(new(big.Int).SetBytes(array[:]))
		break

	case LittleEndian:
		element.SetBigInt(new(big.Int).SetBytes(reverseEndianness(array[:])))
		break
	}

	return element

}

func elementToStandard(element order.Element, endian Endianness) [32]byte {
	var array [32]byte

	switch endian {
	case BigEndian:
		order.BigEndian.PutElement(&array, element)
		break
	case LittleEndian:
		order.LittleEndian.PutElement(&array, element)
		break
	}
	return array
}

func printElement(element order.Element, standardRepresentation bool) {
	var array [32]byte

	if !standardRepresentation {
		binary.LittleEndian.PutUint64((array)[0:8], element[0])
		binary.LittleEndian.PutUint64((array)[8:16], element[1])
		binary.LittleEndian.PutUint64((array)[16:24], element[2])
		binary.LittleEndian.PutUint64((array)[24:32], element[3])
		fmt.Printf("%s\n", hex.EncodeToString(array[:]))
		return
	}

	order.LittleEndian.PutElement(&array, element)

	fmt.Printf("%s\n", hex.EncodeToString(array[:]))

}
