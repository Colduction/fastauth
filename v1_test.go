package fastauth_test

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/colduction/fastauth"
)

func benchPerCoreConfigs(b *testing.B, f func(b *testing.B)) {
	b.Helper()
	coreConfigs := []int{1, 2, 4, 8}
	for _, n := range coreConfigs {
		name := fmt.Sprintf("%d cores", n)
		b.Run(name, func(b *testing.B) {
			runtime.GOMAXPROCS(n)
			f(b)
		})
	}
}

var (
	ct []byte = []byte{91, 105, 153, 222, 78, 98, 65, 105, 136, 146, 81, 118, 116}
	pt []byte = []byte("[i] PlainText")
	pk []byte = []byte("PassKey")

	b64_c      []byte = []byte("W2mZ3k5iQWmIklF2dA")
	salt       []byte = []byte("salt")
	b64_ct     string = "W2mZ3k5iQWmIklF2dA"
	crc        string = "624b9023"
	serialized string = "[80,97,115,115,75,101,121]:624b9023:W2mZ3k5iQWmIklF2dA"
)

// V1.Encrypt
func BenchmarkV1Encrypt(b *testing.B) {
	benchPerCoreConfigs(b, func(b *testing.B) {
		b.RunParallel(func(b *testing.PB) {
			for b.Next() {
				_ = fastauth.V1.Encrypt(pt, pk)
			}
		})
	})
}

// V1.EncryptToB64
func BenchmarkV1EncryptToB64(b *testing.B) {
	benchPerCoreConfigs(b, func(b *testing.B) {
		b.RunParallel(func(b *testing.PB) {
			for b.Next() {
				_ = fastauth.V1.EncryptToB64Raw(ct, pk)
			}
		})
	})
}

// V1.Decrypt
func BenchmarkV1Decrypt(b *testing.B) {
	benchPerCoreConfigs(b, func(b *testing.B) {
		b.RunParallel(func(b *testing.PB) {
			for b.Next() {
				_ = fastauth.V1.Decrypt(ct, pk)
			}
		})
	})
}

// V1.DecryptFromB64
func BenchmarkV1DecryptFromB64(b *testing.B) {
	benchPerCoreConfigs(b, func(b *testing.B) {
		b.RunParallel(func(b *testing.PB) {
			for b.Next() {
				_ = fastauth.V1.DecryptFromB64Raw(b64_ct, pk)
			}
		})
	})
}

// V1.Checksum
func BenchmarkV1Checksum(b *testing.B) {
	benchPerCoreConfigs(b, func(b *testing.B) {
		b.RunParallel(func(b *testing.PB) {
			for b.Next() {
				_, _ = fastauth.V1.Checksum(pk, b64_c, salt)
			}
		})
	})
}

// V1.SerializeToString
func BenchmarkV1SerializeToString(b *testing.B) {
	benchPerCoreConfigs(b, func(b *testing.B) {
		b.RunParallel(func(b *testing.PB) {
			for b.Next() {
				_, _ = fastauth.V1.SerializeToString(b64_c, pk, salt)
			}
		})
	})
}

// V1.Validate
func BenchmarkV1Validate(b *testing.B) {
	benchPerCoreConfigs(b, func(b *testing.B) {
		b.RunParallel(func(b *testing.PB) {
			for b.Next() {
				_ = fastauth.V1.Validate(crc, b64_c, pk, salt)
			}
		})
	})
}

// V1.ValidateSerialized
func BenchmarkV1ValidateSerialized(b *testing.B) {
	benchPerCoreConfigs(b, func(b *testing.B) {
		b.RunParallel(func(b *testing.PB) {
			for b.Next() {
				_ = fastauth.V1.ValidateSerialized(serialized, salt)
			}
		})
	})
}
