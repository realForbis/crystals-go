package kyber

import (
	"fmt"

	"golang.org/x/crypto/blake2s"
)

//AKE struct holds the data used by a participant during one authenticated key exchange protocol.
type AKE struct {
	kybercca *Kyber
	kybercpa *Kyber
	spk      []byte //static public key
	ssk      []byte //static secret key
	spkP     []byte //Correspondant's static public key
	epk      []byte //P1 ephemeral public key
	esk      []byte //P1 ephemeral secret key
	k        []byte //P1's ephemeral key decaps value
	k1       []byte //P1's static key decaps value
	k2       []byte //P2's static key decaps value
	key      []byte //final key material
}

//NewAKE creates an AKE strct based on the party' public and secret keys pair
//and the other party's public key
func NewAKE(spk, ssk, spkP []byte, kcca, kcpa *Kyber) *AKE {
	return &AKE{
		kybercca: kcca,
		kybercpa: kcpa,
		spk:      spk,
		ssk:      ssk,
		spkP:     spkP,
	}
}

//InitMsg is called by P1.
//It updates the AKE struct and create the message to send
func (a *AKE) InitMsg() []byte {
	epk, esk := a.kybercpa.CPAKeyGen()
	a.epk = epk[:]
	a.esk = esk[:]
	c2, k2 := a.kybercca.Encaps(a.spkP, nil)
	a.k2 = k2
	return append(epk, c2...)
}

//ResponseMsg is called by P2.
//It consumes initmsg, updates the ake struc, and create the response
func (a *AKE) ResponseMsg(initMsg []byte) []byte {
	if len(initMsg) != a.kybercca.SIZEC()+a.kybercpa.SIZEPK() {
		fmt.Printf("Init message is not correct. Expecting %d, got %d.\n", a.kybercca.SIZEC()+a.kybercpa.SIZEPK(), len(initMsg))
		return nil
	}
	a.epk = initMsg[:a.kybercpa.SIZEPK()]
	c, k := a.kybercpa.CPAEncaps(a.epk)
	c1, k1 := a.kybercca.Encaps(a.spkP, nil)
	k2 := a.kybercca.Decaps(a.ssk, initMsg[a.kybercpa.SIZEPK():])
	allKs := append(append(k, k1...), k2...)
	key := blake2s.Sum256(allKs)
	a.key = key[:]
	return append(c, c1...)
}

//ConsumeRespMsg is called by P1 as last step of the protocol.
//P1 consumes the resp message, updates their ake struct.
func (a *AKE) ConsumeRespMsg(respMsg []byte) {
	if len(respMsg) != a.kybercca.SIZEC()+a.kybercpa.SIZEC() {
		print("Response message is not correct.\n")
		return
	}
	k := a.kybercpa.CPADecaps(a.esk, respMsg[:a.kybercpa.SIZEC()])
	k1 := a.kybercca.Decaps(a.ssk, respMsg[a.kybercpa.SIZEC():])
	allKs := append(append(k, k1...), a.k2...)
	key := blake2s.Sum256(allKs)
	a.key = key[:]
	return
}

//GetKeyOrNil is the public getter method used to return the key resulting from the ake a.
func (a *AKE) GetKeyOrNil() []byte {
	return a.key
}
