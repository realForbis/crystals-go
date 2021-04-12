package kyber

import "golang.org/x/crypto/blake2s"

type AKE struct {
	kybercca *Kyber
	kybercpa *Kyber
	spk      []byte //static public key
	ssk      []byte //static secret key
	spkP     []byte //Correspondant's static public key
	epk1     []byte //P1 ephemeral public key
	esk1     []byte //P1 ephemeral secret key
	k        []byte //P1's ephemeral key decaps value
	k1       []byte //P1's static key decaps value
	k2       []byte //P2's static key decaps value
	key      []byte //final key material
}

//New AKE creates an AKE strct based on the party' public and secret keys pair
//and the other party's public key
func NewAKE(spk, ssk, spkP []byte, kcca *Kyber, kcpa *Kyber) *AKE {
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
	epk, esk := a.kybercpa.KeyGen(nil)
	a.epk1 = epk[:]
	a.esk1 = esk[:]
	c2, k2 := a.kybercpa.Encaps(nil, a.spkP)
	a.k2 = k2
	return append(epk, c2...)
}

//ResponseMsg is called by P2.
//It consumes initmsg, updates the ake struc, and create the response
func (a *AKE) ResponseMsg(initMsg []byte) []byte {
	if len(initMsg) != a.kybercpa.SIZEC()+a.kybercpa.SIZEPK() {
		print("Init message is not correct.")
		return nil
	}
	a.epk1 = initMsg[:a.kybercpa.SIZEPK()]
	c, k := a.kybercpa.Encaps(nil, a.epk1)
	c1, k1 := a.kybercca.Encaps(nil, a.spkP)
	k2 := a.kybercpa.Decaps(initMsg[a.kybercpa.SIZEPK():], a.ssk)
	allKs := append(append(k, k1...), k2...)
	key := blake2s.Sum256(allKs)
	a.key = key[:]
	return append(c, c1...)
}

func (a *AKE) ConsumeRespMsg(respMsg []byte) {
	if len(respMsg) != a.kybercca.SIZEC()+a.kybercpa.SIZEC() {
		print("Response message is not correct.\n")
		return
	}
	k := a.kybercpa.Decaps(respMsg[:a.kybercpa.SIZEC()], a.esk1)
	k1 := a.kybercca.Decaps(respMsg[a.kybercpa.SIZEC():], a.ssk)
	allKs := append(append(k, k1...), a.k2...)
	key := blake2s.Sum256(allKs)
	a.key = key[:]
	return
}

func (a *AKE) GetKeyOrNil() []byte {
	if a.key == nil {
		return nil
	}
	return a.key
}
