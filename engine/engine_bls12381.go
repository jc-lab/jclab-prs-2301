package engine

import (
	"crypto/rand"
	"go.bryk.io/miracl/core"
	"go.bryk.io/miracl/core/BLS12381"
)

type CurveEngineBls12381Impl struct {
	CurveEngine
	z    *BLS12381.FP12
	rand Rand
}

func ceil(a int, b int) int {
	return (((a)-1)/(b) + 1)
}

func NewBLS12381Engine() (*CurveEngineBls12381Impl, error) {
	z := BLS12381.Ate(BLS12381.ECP2_generator(), BLS12381.ECP_generator())
	z = BLS12381.Fexp(z)

	r := core.NewRAND()

	buf := make([]byte, 1024)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	r.Seed(len(buf), buf)

	rf := func() byte {
		return r.GetByte()
	}

	return &CurveEngineBls12381Impl{
		z:    z,
		rand: rf,
	}, nil
}

func (e *CurveEngineBls12381Impl) SetRandomProvider(rand Rand) {
	e.rand = rand
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
	return 2*BLS12381.BFS + 1
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

func (e *CurveEngineBls12381Impl) BIGToTrimmedBytes(big *BLS12381.BIG) []byte {
	buffer := make([]byte, BLS12381.BGS)
	size := big.Nbits()
	temp := size % 8
	if temp > 0 {
		size += 8 - temp
		size /= 8
	}
	big.ToBytes(buffer)
	prefix := len(buffer) - size
	return buffer[prefix:]
}

func (e *CurveEngineBls12381Impl) KeyPairFromBytes(S []byte) (*KeyPair, error) {
	kp := &KeyPair{
		W1: make([]byte, e.GetG1S()),
		W2: make([]byte, e.GetG2S()),
	}

	s := e.decodePrivateKey(S)
	kp.S = e.BIGToTrimmedBytes(s)

	G1 := BLS12381.ECP_generator()
	G2 := BLS12381.ECP2_generator()

	G1 = BLS12381.G1mul(G1, s)
	G2 = BLS12381.G2mul(G2, s)
	G1.ToBytes(kp.W1, true)
	G2.ToBytes(kp.W2, true)

	return kp, nil
}

type Signable interface {
	sign() int
}

func (e *CurveEngineBls12381Impl) KeyPairGenerateIKM(IKM []byte) (*KeyPair, error) {
	r := e.BIGCurveOrder()
	nbr := r.Nbits()
	L := ceil(3*ceil(nbr, 8), 2)
	LEN := core.InttoBytes(L, 2)

	SALT := []byte("BLS-SIG-KEYGEN-SALT-")
	PRK := core.HKDF_Extract(core.MC_SHA2, 32, SALT, IKM)
	OKM := core.HKDF_Expand(core.MC_SHA2, 32, L, PRK, LEN)

	return e.KeyPairFromBytes(OKM)
}

func (e *CurveEngineBls12381Impl) KeyPairGenerate() (*KeyPair, error) {
	var IKM [64]byte

	for i := 0; i < len(IKM); i++ {
		IKM[i] = e.rand()
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
	s2 := BLS12381.DBIG_fromBytes(ReSignerS)
	s := s2.Mod(r)
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
	h := BLS12381.DBIG_fromBytes(digest)
	return h.Mod(r)
}

func (e *CurveEngineBls12381Impl) Sign(M []byte, S []byte) (*Signature1, error) {
	r := e.BIGCurveOrder()

	kBuf := make([]byte, 32)
	for i := 0; i < 32; i++ {
		kBuf[i] = e.rand()
	}

	k := BLS12381.FromBytes(kBuf)
	k.Mod(r)

	h := e.hashMessage(M)

	rQ := BLS12381.ECP2_generator()
	rQ = BLS12381.G2mul(rQ, k)

	privKey := e.decodePrivateKey(S)
	privKey.Invmodp(r)
	s := BLS12381.Modmul(privKey, k.Plus(h), r)

	result := &Signature1{
		R: make([]byte, e.GetG2S()),
		S: e.BIGToTrimmedBytes(s),
	}

	rQ.ToBytes(result.R, true)

	return result, nil
}

func (e *CurveEngineBls12381Impl) FirstVerify(sig *Signature1, M []byte, W []byte) bool {
	r := e.BIGCurveOrder()
	publicKeyG1 := BLS12381.ECP_fromBytes(W)

	h := e.hashMessage(M)

	s := BLS12381.DBIG_fromBytes(sig.S).Mod(r)
	g2s := BLS12381.ECP2_generator().Mul(s)

	sigR := BLS12381.ECP2_fromBytes(sig.R)
	v1 := BLS12381.Ate(g2s, publicKeyG1)
	v1 = BLS12381.Fexp(v1)

	buf := make([]byte, 1024)

	v1.ToBytes(buf)

	v2 := e.z.Pow(h)
	v2.ToBytes(buf)
	v2b := BLS12381.Ate(sigR, BLS12381.ECP_generator())
	v2b = BLS12381.Fexp(v2b)
	v2.Mul(v2b)
	return v1.Equals(v2)
}

func (e *CurveEngineBls12381Impl) PrsResign(inSig *Signature1, RK []byte) (*Signature2, error) {
	r := e.BIGCurveOrder()

	s2 := BLS12381.ECP2_fromBytes(RK)
	s1 := BLS12381.DBIG_fromBytes(inSig.S).Mod(r)
	s2 = BLS12381.G2mul(s2, s1)

	buf := make([]byte, e.GetG2S())
	s2.ToBytes(buf, true)

	return &Signature2{
		R: inSig.R,
		S: buf,
	}, nil
}

func (e *CurveEngineBls12381Impl) Verify(sig *Signature2, M []byte, W []byte) bool {
	publicKeyG1 := BLS12381.ECP_fromBytes(W)

	h := e.hashMessage(M)

	s := BLS12381.ECP2_fromBytes(sig.S)

	sigR := BLS12381.ECP2_fromBytes(sig.R)
	v1 := BLS12381.Ate(s, publicKeyG1)
	v1 = BLS12381.Fexp(v1)

	buf := make([]byte, 1024)

	v1.ToBytes(buf)

	v2 := e.z.Pow(h)
	v2.ToBytes(buf)
	v2b := BLS12381.Ate(sigR, BLS12381.ECP_generator())
	v2b = BLS12381.Fexp(v2b)
	v2.Mul(v2b)
	return v1.Equals(v2)
}

func (e *CurveEngineBls12381Impl) Signature1FromBytes(data []byte) *Signature1 {
	result := &Signature1{
		R: make([]byte, e.GetG2S()),
		S: make([]byte, 32),
	}
	copy(result.R, data[:len(result.R)])
	copy(result.S, data[len(result.R):])
	return result
}

func (e *CurveEngineBls12381Impl) Signature2FromBytes(data []byte) *Signature2 {
	result := &Signature2{
		R: make([]byte, e.GetG2S()),
		S: make([]byte, e.GetG2S()),
	}
	copy(result.R, data[:len(result.R)])
	copy(result.S, data[len(result.R):])
	return result
}

func (e *CurveEngineBls12381Impl) decodePrivateKey(S []byte) *BLS12381.BIG {
	s2 := BLS12381.DBIG_fromBytes(S)
	return s2.Mod(e.BIGCurveOrder())
}
