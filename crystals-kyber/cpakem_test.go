package kyber

import (
	"bytes"
	"fmt"
	"testing"
)

func BenchmarkCCAKEM(b *testing.B) {
	k := NewKyber512()

	for i := 0; i < b.N; i++ {
		pk, sk := k.KeyGen(nil)
		c, _ := k.Encaps(nil, pk)
		k.Decaps(c, sk)
	}
}

func BenchmarkCCAKEMEncaps(b *testing.B) {
	k := NewKyber512()

	for i := 0; i < b.N; i++ {
		pk, _ := k.KeyGen(nil)
		b.StartTimer()
		k.Encaps(nil, pk)
		b.StopTimer()
	}
}

func BenchmarkCCAKEMDecaps(b *testing.B) {
	k := NewKyber512()

	for i := 0; i < b.N; i++ {
		pk, sk := k.KeyGen(nil)
		c, _ := k.Encaps(nil, pk)
		b.StartTimer()
		k.Decaps(c, sk)
		b.StopTimer()
	}
}

func TestCCAFailure(t *testing.T) {
	k := NewKyber512()
	//testCCAFailureRate(k)
	testSizes(k)
}

func BenchmarkCPAKEM(b *testing.B) {
	k := NewKyber512()

	for i := 0; i < b.N; i++ {
		pk, sk := k.CPAKeyGen()
		c, _ := k.CPAEncaps(pk)
		k.CPADecaps(c, sk)
	}
}

func BenchmarkCPAKEMEncaps(b *testing.B) {
	k := NewKyber512()

	for i := 0; i < b.N; i++ {
		pk, _ := k.CPAKeyGen()
		b.StartTimer()
		k.CPAEncaps(pk)
		b.StopTimer()
	}
}

func BenchmarkCPAKEMDecaps(b *testing.B) {
	k := NewKyber512()

	for i := 0; i < b.N; i++ {
		pk, sk := k.CPAKeyGen()
		c, _ := k.CPAEncaps(pk)
		b.StartTimer()
		k.CPADecaps(c, sk)
		b.StopTimer()
	}
}

func TestCPAFailure(t *testing.T) {
	k := NewKyber512()
	//	testFailureRate(k)
	testSizes(k)
}

func BenchmarkCPAKEMTweaked(b *testing.B) {
	k := NewTweakedKyber512()

	for i := 0; i < b.N; i++ {
		pk, sk := k.CPAKeyGen()
		c, _ := k.CPAEncaps(pk)
		k.CPADecaps(c, sk)
	}
}

func BenchmarkCPAKEMTweakedEncaps(b *testing.B) {
	k := NewKyber512()

	for i := 0; i < b.N; i++ {
		pk, _ := k.CPAKeyGen()
		b.StartTimer()
		k.CPAEncaps(pk)
		b.StopTimer()
	}
}

func BenchmarkCPAKEMTweakedDecaps(b *testing.B) {
	k := NewKyber512()

	for i := 0; i < b.N; i++ {
		pk, sk := k.CPAKeyGen()
		c, _ := k.CPAEncaps(pk)
		b.StartTimer()
		k.CPADecaps(c, sk)
		b.StopTimer()
	}
}

func TestCPATweakedFailure(t *testing.T) {
	k := NewTweakedKyber512()
	testFailureRate(k)
	testSizes(k)
}

func testCCAFailureRate(k *Kyber) {
	failed := 0
	iters := 1000000
	for i := 0; i < iters; i++ {
		pk, sk := k.KeyGen(nil)
		c, ss := k.Encaps(nil, pk)
		ss2 := k.Decaps(c, sk)
		if !bytes.Equal(ss[:], ss2[:]) {
			failed++
		}
	}
	fmt.Printf("\n\nFailed %d out of %d\n", failed, iters)
}

func testFailureRate(k *Kyber) {
	failed := 0
	iters := 1000000
	for i := 0; i < iters; i++ {
		pk, sk := k.CPAKeyGen()
		c, ss := k.CPAEncaps(pk)
		ss2 := k.CPADecaps(c, sk)
		if !bytes.Equal(ss[:], ss2[:]) {
			failed++
		}
	}
	fmt.Printf("Failed %d out of %d\n", failed, iters)
}

func testSizes(k *Kyber) {
	fmt.Printf("Size public key %d, ciphertext %d\n", k.SIZEPK(), k.SIZEC())
}
