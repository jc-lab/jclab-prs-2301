package engine

import (
	"github.com/jc-lab/miracl_wrapper"
	"go.bryk.io/miracl/core"
	"go.bryk.io/miracl/core/BLS12381"
)

type CurveEngineBls12381Impl struct {
	z *BLS12381.FP12
}

func ceil(a int, b int) int {
	return (((a)-1)/(b) + 1)
}

func NewBLS12381Engine() *CurveEngineBls12381Impl {
	z := BLS12381.Ate(BLS12381.ECP2_generator(), BLS12381.ECP_generator())
	return &CurveEngineBls12381Impl{
		z: z,
	}
}

func (e *CurveEngineBls12381Impl) GetBGS() int {
	return BLS12381.BGS
}

func (e *CurveEngineBls12381Impl) GetBFS() int {
	return BLS12381.BFS
}

func (e *CurveEngineBls12381Impl) GetG1S() int {
	return BLS12381.BFS + 1
}

func (e *CurveEngineBls12381Impl) GetG2S() int {
	return 8 * BLS12381.BFS + 1
}

func (e *CurveEngineBls12381Impl) GetSecretKeySize() int {
	return e.GetBGS()
}

func (e *CurveEngineBls12381Impl) GetPublicKeySize() int {
	return e.GetG2S()
}

func (e *CurveEngineBls12381Impl) BIGCurveOrder() *BLS12381.BIG {
	return BLS12381.NewBIGints(BLS12381.CURVE_Order)
}

func (e *CurveEngineBls12381Impl) KeyPairGenerateIKM(IKM []byte) (*KeyPair, error) {
	kp := &KeyPair{
		S:  make([]byte, e.GetBGS()),
		W:  make([]byte, e.GetG1S()),
		W2: make([]byte, e.GetG2S()),
	}
	
	r := e.BIGCurveOrder()
	nbr := r.Nbits()
	L := ceil(3*ceil(nbr, 8), 2)
	LEN := core.InttoBytes(L, 2)

	SALT := []byte("BLS-SIG-KEYGEN-SALT-")
	PRK := core.HKDF_Extract(core.MC_SHA2, 32, SALT, IKM)
	OKM := core.HKDF_Expand(core.MC_SHA2, 32, L, PRK, LEN)

	s := BLS12381.FromBytes(OKM)
	s.Mod(r)
	s.ToBytes(kp.S)

	G1 := BLS12381.ECP_generator()
	G2 := BLS12381.ECP2_generator()

	G1 = BLS12381.G1mul(G1, s)
	G2 = BLS12381.G2mul(G2, s)
	G1.ToBytes(kp.W, true)
	G2.ToBytes(kp.W2, true)

	return kp, nil
}

func (e *CurveEngineBls12381Impl) KeyPairGenerate(rng *core.RAND) (*KeyPair, error) {
	var IKM [64]byte

	for i := 0; i < len(IKM); i++ {
		IKM[i] = byte(rng.GetByte())
	}

	return e.KeyPairGenerateIKM(IKM[:])
}

func (e *CurveEngineBls12381Impl) GeneratePublicKey(S []byte) ([]byte, error) {
	s := BLS12381.FromBytes(S)
	G := BLS12381.ECP_generator()
	G = BLS12381.G1mul(G, s)
	W := make([]byte, e.GetG2S())
	G.ToBytes(W, true)
	return W, nil
}

func (e *CurveEngineBls12381Impl) PrsResigningKey(SignerW2 []byte, ReSignerS []byte) ([]byte, error) {
	r := e.BIGCurveOrder()

	G2 := BLS12381.ECP2_fromBytes(SignerW2)
	s := BLS12381.FromBytes(ReSignerS)

	s.Invmodp(r)
	RK := BLS12381.G2mul(G2, s)

	buf := make([]byte, e.GetG2S())
	RK.ToBytes(buf, true)

	return buf, nil
}

func (e *CurveEngineBls12381Impl) hashMessage(M []byte) *BLS12381.BIG {
	r := e.BIGCurveOrder()
	hash := core.NewHASH256()
	hash.Process_array(M)
	digest := hash.Hash()
	h := BLS12381.FromBytes(digest)
	h.Mod(r)
	return h
}

func (e *CurveEngineBls12381Impl) Sign(M []byte, S []byte) (*Signature1, error) {
	r := e.BIGCurveOrder()

	kBuf := make([]byte, 32)
	k := BLS12381.FromBytes(kBuf)
	k.Mod(r)

	h := e.hashMessage(M)

	rQ := BLS12381.ECP2_generator()
	rQ = BLS12381.G2mul(rQ, k)

	privKey := BLS12381.FromBytes(S)
	privKey.Invmodp(r)
	s := BLS12381.Modmul(privKey, k.Plus(h), r)

	result := &Signature1{
		R: make([]byte, e.GetG2S()),
		S: make([]byte, e.GetBGS()),
	}

	rQ.ToBytes(result.R, true)
	s.ToBytes(result.S)

	return result, nil
}

func (e *CurveEngineBls12381Impl) FirstVerify(sig *Signature1, M []byte, W []byte) int {
	publicKeyG1 := BLS12381.ECP_fromBytes(W)
	g2s := BLS12381.ECP2_generator().Mul(BLS12381.FromBytes(sig.S))

	r := e.BIGCurveOrder()
	h := e.hashMessage(M)
	v1 := BLS12381.Ate(g2s, publicKeyG1)
	v2a := BLS12381.FP12.po

	v1 := e.
}

func (e *CurveEngineBls12381Impl) PrsResign(inSig *Signature1, RK []byte) (*Signature2, error) {
	s2 := BLS12381.ECP2_fromBytes(RK)
	s1 := BLS12381.FromBytes(inSig.S)
	s2 = BLS12381.G2mul(s2, s1)

	buf := make([]byte, e.GetG2S())
	s2.ToBytes(buf, true)

	return &Signature2{
		R: inSig.R,
		S: buf,
	}, nil
}

func (e *CurveEngineBls12381Impl) Verify(sig *Signature2, M []byte, W []byte) int {
	r := e.BIGCurveOrder()
	h := e.hashMessage(M)

	//TODO implement me
	panic("implement me")
}
