package kyber

import (
	"bytes"
	"testing"
)

func TestAKE(t *testing.T) {
	kybercca := NewKyber512()
	kybercpa := NewTweakedKyber512()
	spk1, ssk1 := kybercca.KeyGen(nil)
	spk2, ssk2 := kybercca.KeyGen(nil)

	/**P1**/
	ake1 := NewAKE(spk1, ssk1, spk2, kybercca, kybercpa)
	initMsg := ake1.InitMsg()

	/**P2**/
	ake2 := NewAKE(spk2, ssk2, spk1, kybercca, kybercpa)
	respMsg := ake2.ResponseMsg(initMsg)

	/**P1**/
	ake1.ConsumeRespMsg(respMsg)

	if ake1.GetKeyOrNil() == nil {
		t.Fatal("Keys are nil")
	}
	if !bytes.Equal(ake1.GetKeyOrNil(), ake2.GetKeyOrNil()) {
		t.Fatal("Keys are not equal")
	}
}

func TestGetKeyTooSoon(t *testing.T) {
	kybercca := NewKyber512()
	kybercpa := NewTweakedKyber512()
	spk1, ssk1 := kybercca.KeyGen(nil)

	ake1 := NewAKE(spk1, ssk1, spk1, kybercca, kybercpa)
	if ake1.GetKeyOrNil() != nil {
		t.Fatal("Should return nil")
	}
}

func BenchmarkAKE(b *testing.B) {
	kybercca := NewKyber512()
	kybercpa := NewTweakedKyber512()

	spk1, ssk1 := kybercca.KeyGen(nil)
	spk2, ssk2 := kybercpa.KeyGen(nil)

	ake1 := NewAKE(spk1, ssk1, spk2, kybercca, kybercpa)
	ake2 := NewAKE(spk2, ssk2, spk1, kybercca, kybercpa)
	for n := 0; n < b.N; n++ {
		initMsg := ake1.InitMsg()
		respMsg := ake2.ResponseMsg(initMsg)
		ake1.ConsumeRespMsg(respMsg)
	}
}

func BenchmarkAKEInit(b *testing.B) {
	kybercca := NewKyber512()
	kybercpa := NewTweakedKyber512()
	spk1, ssk1 := kybercca.KeyGen(nil)
	spk2, _ := kybercpa.KeyGen(nil)

	ake1 := NewAKE(spk1, ssk1, spk2, kybercca, kybercpa)
	for n := 0; n < b.N; n++ {
		ake1.InitMsg()
	}
}

func BenchmarkAKEResp(b *testing.B) {
	kybercca := NewKyber512()
	kybercpa := NewTweakedKyber512()
	spk1, ssk1 := kybercca.KeyGen(nil)
	spk2, ssk2 := kybercpa.KeyGen(nil)

	ake1 := NewAKE(spk1, ssk1, spk2, kybercca, kybercpa)
	ake2 := NewAKE(spk2, ssk2, spk1, kybercca, kybercpa)
	initMsg := ake1.InitMsg()
	for n := 0; n < b.N; n++ {
		ake2.ResponseMsg(initMsg)
	}
}

func BenchmarkAKEConsumResp(b *testing.B) {
	kybercca := NewKyber512()
	kybercpa := NewTweakedKyber512()
	spk1, ssk1 := kybercca.KeyGen(nil)
	spk2, ssk2 := kybercpa.KeyGen(nil)

	ake1 := NewAKE(spk1, ssk1, spk2, kybercca, kybercpa)
	ake2 := NewAKE(spk2, ssk2, spk1, kybercca, kybercpa)
	initMsg := ake1.InitMsg()
	respMsg := ake2.ResponseMsg(initMsg)
	for n := 0; n < b.N; n++ {
		ake1.ConsumeRespMsg(respMsg)
	}
}
