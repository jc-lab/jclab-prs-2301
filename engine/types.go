package engine

import "go.bryk.io/miracl/core"

type KeyPair struct {
	S  []byte // private
	W  []byte // public G1
	W2 []byte // public G2
}

type Signature1 struct {
	R []byte
	S []byte
}

type Signature2 struct {
	R []byte
	S []byte
}

type CurveEngine interface {
	GetBGS() int
	GetBFS() int
	GetG1S() int
	GetG2S() int
	GetSecretKeySize() int
	GetPublicKeySize() int
	KeyPairGenerateIKM(IKM []byte) (*KeyPair, error)
	KeyPairGenerate(rng *core.RAND) (*KeyPair, error)
	GeneratePublicKey(S []byte) ([]byte, error)

	Sign(M []byte, S []byte) (*Signature1, error)
	FirstVerify(sig *Signature1, M []byte, W []byte) int
	Verify(sig *Signature2, M []byte, W []byte) int

	PrsResigningKey(SignerW2 []byte, ReSignerS []byte) ([]byte, error)
	PrsResign(inSig *Signature1, RK []byte) (*Signature2, error)
}