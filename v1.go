package fastauth

import (
	"encoding/base64"
	"hash/crc64"
	"strconv"
	"strings"
	"unsafe"

	jsoniter "github.com/json-iterator/go"
)

type version1 struct{}

// XOR encryption with small changes
var V1 version1

var json = jsoniter.ConfigFastest

// Encrypt input using XOR operation with small changes
func (version1) Encrypt(input, key []byte) []byte {
	inputLen, keyLen := len(input), len(key)
	if inputLen == 0 || keyLen == 0 {
		return nil
	}
	kli := keyLen - 1 // Key last index position
	out := make([]byte, inputLen)
	i := 0
	for j, b := range input {
		if i >= kli {
			i = 0
		}
		out[j] = (b - key[i]) ^ key[i]
		i++
	}
	return out
}

// Encrypt input using XOR operation with small changes to Base64 Raw URL encoded text
func (version1) EncryptToB64Raw(input, key []byte) string {
	v := V1.Encrypt(input, key)
	if v == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(v)
}

// Decrypt input using XOR operation with small changes
func (version1) Decrypt(input, key []byte) []byte {
	inputLen, keyLen := len(input), len(key)
	if inputLen == 0 || keyLen == 0 {
		return nil
	}
	kli := keyLen - 1 // Key last index position
	out := make([]byte, inputLen)
	i := 0
	for j, b := range input {
		if i >= kli {
			i = 0
		}
		out[j] = (b ^ key[i]) + key[i]
		i++
	}
	return out
}

// Decrypt Base64 Raw URL encoded input using XOR operation with small changes
func (version1) DecryptFromB64Raw(input string, key []byte) []byte {
	v, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		return nil
	}
	return V1.Decrypt(v, key)
}

// Decrypt cipher then unmarshal it to v struct
func (version1) Unmarshal(input, key []byte, v interface{}) error {
	if len(input) == 0 || len(key) == 0 {
		return NewInvalidInputErr(V1.Unmarshal)
	}
	data := V1.Decrypt(input, key)
	return json.Unmarshal(data, v)
}

// Marshal v struct then encrypt it to cipher
func (version1) Marshal(v interface{}, key []byte) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return V1.Encrypt(data, key), nil
}

// Compute CRC-64 checksum of inputs
func (version1) Checksum(inputs ...[]byte) (string, error) {
	if len(inputs) == 0 {
		return "", NewInvalidInputErr(V1.SerializeToString)
	}
	h := crc64.New(crc64.MakeTable(0xC96C5795D7870F42))
	for _, in := range inputs {
		h.Write(in)
	}
	digest := strconv.FormatUint(h.Sum64(), 16)
	h.Reset()
	return digest, nil
}

// Serialize b64 cipher, key and salt to string
func (version1) SerializeToString(b64, key, salt []byte) (string, error) {
	if len(b64) == 0 || len(key) == 0 || len(salt) == 0 {
		return "", NewInvalidInputErr(V1.SerializeToString)
	}
	digest, err := V1.Checksum(key, b64, salt)
	if err != nil {
		return "", err
	}
	sb := strings.Builder{}
	sb.Grow(20)
	iKey := make([]int, len(key))
	for i, num := range key {
		iKey[i] = int(num)
	}
	k, err := json.Marshal(&iKey)
	if err != nil {
		return "", err
	}
	sb.WriteString(unsafe.String(unsafe.SliceData(k), len(k)))
	sb.WriteByte(':')
	if len(digest) >= 8 {
		sb.WriteString(digest[0:8])
	} else {
		sb.WriteString(digest)
	}
	sb.WriteByte(':')
	sb.WriteString(unsafe.String(unsafe.SliceData(b64), len(b64)))
	return sb.String(), nil
}

// Validate crc checksum by comapring the CRC-64 checksum of inputs
func (version1) Validate(crc string, inputs ...[]byte) error {
	if len(inputs) == 0 {
		return NewInvalidInputErr(V1.Validate)
	}
	digest, err := V1.Checksum(inputs...)
	if err != nil {
		return err
	}
	if len(digest) >= len(crc) && digest[0:len(crc)] == crc {
		return nil
	}
	return NewInvalidInputErr(V1.Validate)
}

// Validate the serialized string
func (version1) ValidateSerialized(s string, salt []byte) error {
	if len(s) == 0 {
		return NewInvalidInputErr(V1.ValidateSerialized)
	}
	tmp := strings.SplitN(s, ":", 3)
	if len(tmp) != 3 {
		return NewInvalidInputErr(V1.ValidateSerialized)
	}
	var key []byte = make([]byte, 0)
	err := json.Unmarshal(unsafe.Slice(unsafe.StringData(tmp[0]), len(tmp[0])), &key)
	if err != nil {
		return err
	}
	return V1.Validate(tmp[1], key, unsafe.Slice(unsafe.StringData(tmp[2]), len(tmp[2])), salt)
}
