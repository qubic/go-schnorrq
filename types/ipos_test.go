package types

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIpos_UnmarshallFromReader(t *testing.T) {
	activeIpoHeader, err := base64.StdEncoding.DecodeString("FAAAQehMlcw=")
	require.NoError(t, err)

	activeIpoPayload, err := base64.StdEncoding.DecodeString("EwAAAFExOTAxAAAA")
	require.NoError(t, err)

	activeIpo2Header, err := base64.StdEncoding.DecodeString("FAAAQehMlcw=")
	require.NoError(t, err)

	activeIpo2Payload, err := base64.StdEncoding.DecodeString("FAAAAFExOTAyAAAA")
	require.NoError(t, err)

	endResponseHeader, err := base64.StdEncoding.DecodeString("CAAAI/PqVtQ=")
	require.NoError(t, err)

	message := make([]byte, 0)
	message = append(message, activeIpoHeader...)
	message = append(message, activeIpoPayload...)
	message = append(message, activeIpo2Header...)
	message = append(message, activeIpo2Payload...)
	message = append(message, endResponseHeader...)

	var result Ipos
	err = result.UnmarshallFromReader(bytes.NewReader(message))
	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, 19, int(result[0].ContractIndex))
	assert.Equal(t, []byte("Q1901\x00\x00\x00"), result[0].AssetName[:])
	assert.Equal(t, 20, int(result[1].ContractIndex))
	assert.Equal(t, []byte("Q1902\x00\x00\x00"), result[1].AssetName[:])
}

func TestIpo_UnmarshallBinary(t *testing.T) {
	payload, err := base64.StdEncoding.DecodeString("KgAAAFRFU1QAAAAA")
	require.NoError(t, err)
	var result Ipo
	err = result.UnmarshallBinary(bytes.NewReader(payload))
	require.NoError(t, err)
	assert.Equal(t, 42, int(result.ContractIndex))
	assert.Equal(t, []byte("TEST\x00\x00\x00\x00"), result.AssetName[:])
}

func TestContractIpo_UnmarshallFromReader(t *testing.T) {
	expected := ContractIpo{
		ContractIndex: 5,
		TickNumber:    12345678,
	}
	expected.PubKeys[0] = [32]byte{0x01, 0x02, 0x03}
	expected.PubKeys[675] = [32]byte{0xAA, 0xBB, 0xCC}
	expected.Prices[0] = 1000000
	expected.Prices[675] = -500

	var buffer bytes.Buffer

	testHeader := RequestResponseHeader{
		Type: ContractIpoResponse,
	}
	testHeader.RandomizeDejaVu()
	testHeader.SetSize(uint32(binary.Size(testHeader) + binary.Size(expected)))

	err := binary.Write(&buffer, binary.BigEndian, testHeader)
	require.NoError(t, err)
	err = binary.Write(&buffer, binary.LittleEndian, expected)
	require.NoError(t, err)

	var got ContractIpo
	err = got.UnmarshallFromReader(&buffer)
	require.NoError(t, err)

	if diff := cmp.Diff(expected, got); diff != "" {
		t.Fatalf("mismatch (-expected +got):\n%s", diff)
	}
}
