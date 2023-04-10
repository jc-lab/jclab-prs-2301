package engine

import (
	"bytes"
	"encoding/hex"
	"go.bryk.io/miracl/core"
	"testing"
)

func TestCurveEngineImpl_Prs(t *testing.T) {
	rng := core.NewRAND()

	e := NewCurveEngineBLS12381()
	aliceKey, _ := e.KeyPairGenerate(rng)
	bobKey, _ := e.KeyPairGenerate(rng)

	println(hex.EncodeToString(bobKey.S))
	println(hex.EncodeToString(bobKey.W))

	designatedKey, _ := e.PrsDesignatedKey(aliceKey.S, bobKey.W)
	resignKey, _ := e.PrsResigningKey(bobKey.S, aliceKey.W)

	msg := []byte("HELLO WORLD")

	sigAlice, _ := e.Sign(msg, designatedKey)
	sigBob, _ := e.PrsResign(sigAlice, resignKey)

	r := e.Verify(sigBob, msg, bobKey.W)

	if r != 0 {
		t.Errorf("signature verify failed: %d", r)
	}

	sigAlice2, _ := e.Sign(msg, designatedKey)
	println("SAME = ", bytes.Compare(sigAlice, sigAlice2))

	//r2 := e.FirstVerify(sigAlice, msg, bobKey.W)
	//
	//if r2 != 0 {
	//	t.Errorf("signature verify failed: %d", r)
	//}
}
