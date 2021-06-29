package kyber

import (
	"bytes"
	"fmt"
	"testing"
)

/** CCA **/
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

/** CPA **/

func BenchmarkCPAKEM(b *testing.B) {
	k := NewKyber512()

	for i := 0; i < b.N; i++ {
		pk, sk := k.CPAKeyGen()
		c, _ := k.CPAEncaps(pk)
		k.CPADecaps(sk, c)
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
		k.CPADecaps(sk, c)
		b.StopTimer()
	}
}

/** Tweaked CPA **/
func BenchmarkCPAKEMTweaked(b *testing.B) {
	k := NewTweakedKyber512()

	for i := 0; i < b.N; i++ {
		pk, sk := k.CPAKeyGen()
		c, _ := k.CPAEncaps(pk)
		k.CPADecaps(sk, c)
	}
}

func BenchmarkCPAKEMTweakedEncaps(b *testing.B) {
	k := NewTweakedKyber512()

	for i := 0; i < b.N; i++ {
		pk, _ := k.CPAKeyGen()
		b.StartTimer()
		k.CPAEncaps(pk)
		b.StopTimer()
	}
}

func BenchmarkCPAKEMTweakedDecaps(b *testing.B) {
	k := NewTweakedKyber512()

	for i := 0; i < b.N; i++ {
		pk, sk := k.CPAKeyGen()
		c, _ := k.CPAEncaps(pk)
		b.StartTimer()
		k.CPADecaps(sk, c)
		b.StopTimer()
	}
}

func TestCPATweakedFailure(t *testing.T) {
	k := NewTweakedKyber512()
	failed := 0
	iters := 10000000
	for i := 0; i < iters; i++ {
		pk, sk := k.CPAKeyGen()
		c, ss := k.CPAEncaps(pk)
		ss2 := k.CPADecaps(sk, c)
		if !bytes.Equal(ss[:], ss2[:]) {
			failed++
		}
	}
	fmt.Printf("Failed %d out of %d\n", failed, iters)
}
