package fastauth

import (
	"encoding/base64"
	"encoding/json"
)

type version1 struct{}

// XOR encryption with small changes
var V1 version1

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
func (version1) Unmarshal(input, key []byte, v *interface{}) error {
	if len(input) == 0 || len(key) == 0 {
		return NewInvalidInputErr(V1.Unmarshal)
	}
	data := V1.Decrypt(input, key)
	return json.Unmarshal(data, v)
}

// Marshal v struct then encrypt it to cipher
func (version1) Marshal(v *interface{}, key []byte) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return V1.Encrypt(data, key), nil
}
