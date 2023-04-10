package engine

import (
	"github.com/jc-lab/miracl_wrapper"
	"go.bryk.io/miracl/core"
)

type CurveEngineImpl struct {
	BGS     int
	BFS     int
	G1S     int
	G2S     int
	reflect miracl_wrapper.CurveReflect
}

func ceil(a int, b int) int {
	return (((a)-1)/(b) + 1)
}

func NewBLS12381Engine() CurveEngine {
	reflect := miracl_wrapper.NewCurveReflectWithBLS12381()
	return &CurveEngineImpl{
		BGS:     reflect.GetBGS(),
		BFS:     reflect.GetBFS(),
		G1S:     reflect.GetG1S(),
		G2S:     reflect.GetG2S(),
		reflect: reflect,
	}
}

func (e *CurveEngineImpl) GetBGS() int {
	return e.BGS
}

func (e *CurveEngineImpl) GetBFS() int {
	return e.BFS
}

func (e *CurveEngineImpl) GetG1S() int {
	return e.G1S
}

func (e *CurveEngineImpl) GetG2S() int {
	return e.G2S
}

func (e *CurveEngineImpl) GetSecretKeySize() int {
	return e.BGS
}

func (e *CurveEngineImpl) GetPublicKeySize() int {
	return e.G2S
}

func (e *CurveEngineImpl) KeyPairGenerateIKM(IKM []byte) (*KeyPair, error) {
	kp := &KeyPair{
		S:  make([]byte, e.BGS),
		W:  make([]byte, e.G1S),
		W2: make([]byte, e.G2S),
	}

	r := e.reflect.BIGCurveOrder()
	nbr := r.Nbits()
	L := ceil(3*ceil(nbr, 8), 2)
	LEN := core.InttoBytes(L, 2)

	SALT := []byte("BLS-SIG-KEYGEN-SALT-")
	PRK := core.HKDF_Extract(core.MC_SHA2, 32, SALT, IKM)
	OKM := core.HKDF_Expand(core.MC_SHA2, 32, L, PRK, LEN)

	s := e.reflect.FromBytes(OKM)
	s.Mod(r)
	s.ToBytes(kp.S)

	G1 := e.reflect.ECPGenerator()
	G2 := e.reflect.ECP2Generator()

	G1 = e.reflect.G1mul(G1, s)
	G2 = e.reflect.G2mulEcp2(G2, s)
	G1.ToBytes(kp.W, true)
	G2.ToBytes(kp.W2, true)

	return kp, nil
}

func (e *CurveEngineImpl) KeyPairGenerate(rng *core.RAND) (*KeyPair, error) {
	var IKM [64]byte

	for i := 0; i < len(IKM); i++ {
		IKM[i] = byte(rng.GetByte())
	}

	return e.KeyPairGenerateIKM(IKM[:])
}

func (e *CurveEngineImpl) GeneratePublicKey(S []byte) ([]byte, error) {
	s := e.reflect.FromBytes(S)
	G := e.reflect.ECPGenerator()
	G = e.reflect.G1mul(G, s)
	W := make([]byte, e.G2S)
	G.ToBytes(W, true)
	return W, nil
}

func (e *CurveEngineImpl) PrsResigningKey(SignerW2 []byte, ReSignerS []byte) ([]byte, error) {
	r := e.reflect.BIGCurveOrder()

	G2 := e.reflect.ECP2FromBytes(SignerW2)
	s := e.reflect.FromBytes(ReSignerS)

	s.Invmodp(r)
	RK := e.reflect.G2mulEcp2(G2, s)

	buf := make([]byte, e.reflect.GetG2S())
	RK.ToBytes(buf, true)

	return buf, nil
}

func (e *CurveEngineImpl) hashMessage(M []byte) miracl_wrapper.BIGInterface {
	r := e.reflect.BIGCurveOrder()
	hash := core.NewHASH256()
	hash.Process_array(M)
	digest := hash.Hash()
	h := e.reflect.FromBytes(digest)
	h.Mod(r)
	return h
}

func (e *CurveEngineImpl) Sign(M []byte, S []byte) (*Signature1, error) {
	r := e.reflect.BIGCurveOrder()

	kBuf := make([]byte, 32)
	k := e.reflect.FromBytes(kBuf)
	k.Mod(r)

	h := e.hashMessage(M)

	rQ := e.reflect.ECP2Generator()
	rQ = e.reflect.G2mulEcp2(rQ, k)

	privKey := e.reflect.FromBytes(S)
	privKey.Invmodp(r)
	s := e.reflect.Modmul(privKey, k.Plus(h), r)

	result := &Signature1{
		R: make([]byte, e.reflect.GetG2S()),
		S: make([]byte, e.reflect.GetBGS()),
	}

	rQ.ToBytes(result.R, true)
	s.ToBytes(result.S)

	return result, nil
}

func (e *CurveEngineImpl) FirstVerify(sig *Signature1, M []byte, W []byte) int {
	r := e.reflect.BIGCurveOrder()
	h := e.hashMessage(M)

	v1 := e.reflect.
}

func (e *CurveEngineImpl) PrsResign(inSig *Signature1, RK []byte) (*Signature2, error) {
	s2 := e.reflect.ECP2FromBytes(RK)
	s1 := e.reflect.FromBytes(inSig.S)
	s2 = e.reflect.G2mulEcp2(s2, s1)

	buf := make([]byte, e.reflect.GetG2S())
	s2.ToBytes(buf, true)

	return &Signature2{
		R: inSig.R,
		S: buf,
	}, nil
}

func (e *CurveEngineImpl) Verify(sig *Signature2, M []byte, W []byte) int {
	r := e.reflect.BIGCurveOrder()
	h := e.hashMessage(M)

	//TODO implement me
	panic("implement me")
}
