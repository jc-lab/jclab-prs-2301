package engine

import (
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"go.bryk.io/miracl/core"
	"testing"
	"time"
)

func Test_BLS12381_ReproducibleCase(t *testing.T) {
	e := NewBLS12381Engine()

	bytes, _ := hex.DecodeString("1282a07a980e79ac66b81c6c9f22cf3544fac7f7ddc473e178646d58a88c0c4f")
	aliceKey, _ := e.KeyPairFromBytes(bytes)

	assert.Equal(t, hex.EncodeToString(aliceKey.S), "000000000000000000000000000000001282a07a980e79ac66b81c6c9f22cf3544fac7f7ddc473e178646d58a88c0c4f")
	assert.Equal(t, hex.EncodeToString(aliceKey.W1), "0213fa33245c2b8155804330a84f065895830395df57b47887788d82d6ec82dbc0fdabcd3dd9f0fd7aa3bf9b68be3605df")
	assert.Equal(t, hex.EncodeToString(aliceKey.W2), "03026be1458932fb271f53ae9c41eacbbd739362d8ac2fba3d32d7c0935f186a55bed16661491d38493e466e321f4a97f00cd982e56976360d8fd03516658b6262ff1bf8c7d9a7b1d5478da438769d37fb53ac50f63477ead0216f1d78b4f8a889")

	bytes, _ = hex.DecodeString("341340255f876d1c446080f77ff44ec0518014776cd292df2901a63dd6df7f53")
	bobKey, _ := e.KeyPairFromBytes(bytes)

	assert.Equal(t, hex.EncodeToString(bobKey.S), "00000000000000000000000000000000341340255f876d1c446080f77ff44ec0518014776cd292df2901a63dd6df7f53")
	assert.Equal(t, hex.EncodeToString(bobKey.W1), "0306d5b0d11004f2b12f9beac4fb5b02e671ba96bb638af174a55bc1904c62b05588a7e2bc37c1a123075f8308c463c391")
	assert.Equal(t, hex.EncodeToString(bobKey.W2), "0300c54b72b75ea321b54e072d122338d019710e57dd30234bcc3624dffb4be75b4a1adecc924aada34f655f8c33147fff0790ad1ae160196688c2cf4fe3e7a82d578d00e1bf3da77c85d91f793203d6778eb9957000c2a1469d5a04504e53fd7f")

	resignKey, _ := e.PrsResigningKey(aliceKey.W2, bobKey.S)
	assert.Equal(t, hex.EncodeToString(resignKey), "030ac31b09847297f28cadb0fe88707553e7e9e041010c3d1ad3067c601506f4819f55da80bcd84cecc7508d73d9b89f0215464449b04275fa35752d6a3f8c571228371683004c0b164045b7b460c90db0b88387b895c80fa2e010af8ab5aecced")

	msg := []byte("hello world")

	sigAliceBytes, _ := hex.DecodeString("0209e3164cfe2b5dd8839d0a12d2ddc2b48c9402d103a021163c547d7099ab7d08bd74980c8d330ab0532bc93d6485815a00604536cf702d563c3b1fcd7efba451edcfd67376fed216f4c6994cd01063a817730eae7af863956482817b11f5372607b5cf944cf636cfb4f681d508aa4b01a66fe11f8f1115a9ed6b1c3656c2bab3")
	sigAlice := e.Signature1FromBytes(sigAliceBytes)

	sigAlice2, _ := e.Sign(msg, aliceKey.S)
	assert.Equal(t, len(sigAlice.Encode()), len(sigAlice2.Encode()))

	r := e.FirstVerify(sigAlice, msg, aliceKey.W1)
	assert.True(t, r)

	sigBob, _ := e.PrsResign(sigAlice, resignKey)
	assert.Equal(t, hex.EncodeToString(sigBob.Encode()), "0209e3164cfe2b5dd8839d0a12d2ddc2b48c9402d103a021163c547d7099ab7d08bd74980c8d330ab0532bc93d6485815a00604536cf702d563c3b1fcd7efba451edcfd67376fed216f4c6994cd01063a817730eae7af863956482817b11f53726030f8e48a513cac737e946f24216838afccb66161550f19e44a277c23091305cb6d75141da53d9de8174eff03da2d52d0a016a84720065856163b97b8014ced93b691528c4e52e7da2ed1c98c29925cedd9658f4a1b5412bea35ab97de2d10ace4")

	r = e.Verify(sigBob, msg, bobKey.W1)
	assert.True(t, r)
}

func Test_BLS12381_Random(t *testing.T) {
	e := NewBLS12381Engine()

	message := []byte("HELLO WORLD")

	random := core.NewRAND()

	totalKeyPairGen := int64(0)
	totalReSignKey := int64(0)
	totalSign := int64(0)
	totalVerifyFirst := int64(0)
	totalReSign := int64(0)
	totalVerifySecond := int64(0)

	iterations := 10
	for i := 0; i < iterations; i++ {
		start := time.Now()
		alice, _ := e.KeyPairGenerate(random)
		bob, _ := e.KeyPairGenerate(random)
		totalKeyPairGen += time.Since(start).Milliseconds()

		alice2, _ := e.KeyPairFromBytes(alice.S)
		bob2, _ := e.KeyPairFromBytes(bob.S)

		assert.Equal(t, alice.S, alice2.S)
		assert.Equal(t, alice.W1, alice2.W1)
		assert.Equal(t, alice.W2, alice2.W2)

		assert.Equal(t, bob.S, bob2.S)
		assert.Equal(t, bob.W1, bob2.W1)
		assert.Equal(t, bob.W2, bob2.W2)

		start = time.Now()
		rekey, _ := e.PrsResigningKey(alice.W2, bob.S)
		totalReSignKey += time.Since(start).Milliseconds()

		start = time.Now()
		s1, _ := e.Sign(message, alice.S)
		totalSign += time.Since(start).Milliseconds()

		start = time.Now()
		r := e.FirstVerify(s1, message, alice.W1)
		totalVerifyFirst += time.Since(start).Milliseconds()
		assert.True(t, r)

		start = time.Now()
		s2, _ := e.PrsResign(s1, rekey)
		totalReSign += time.Since(start).Milliseconds()

		start = time.Now()
		r = e.Verify(s2, message, bob.W1)
		totalVerifySecond += time.Since(start).Milliseconds()
		assert.True(t, r)
	}

	avgKeyPairGen := float64(totalKeyPairGen) / float64(iterations*2)
	avgReSignKey := float64(totalReSignKey) / float64(iterations)
	avgSign := float64(totalSign) / float64(iterations)
	avgVerifyFirst := float64(totalVerifyFirst) / float64(iterations)
	avgReSign := float64(totalReSign) / float64(iterations)
	avgVerifySecond := float64(totalVerifySecond) / float64(iterations)

	fmt.Printf("average key pair gen: %.2f ms (%.1f op/s)\n", avgKeyPairGen, 1000.0/avgKeyPairGen)
	fmt.Printf("average re-sign key gen: %.2f ms (%.1f op/s)\n", avgReSignKey, 1000.0/avgReSignKey)
	fmt.Printf("average sign: %.2f ms (%.1f op/s)\n", avgSign, 1000.0/avgSign)
	fmt.Printf("average first verify: %.2f ms (%.1f op/s)\n", avgVerifyFirst, 1000.0/avgVerifyFirst)
	fmt.Printf("average re-sign: %.2f ms (%.1f op/s)\n", avgReSign, 1000.0/avgReSign)
	fmt.Printf("average second verify: %.2f ms (%.1f op/s)\n", avgVerifySecond, 1000.0/avgVerifySecond)
}
