package sm2

import (
	"crypto/rand"
	"testing"
)

const (
	KeyBits = 128
)

var (
	initiatorId = []byte("ABCDEFG1234")
	responderId = []byte("1234567ABCD")
)

func TestSM2KeyExchange(t *testing.T) {
	initiatorStaticPriv, initiatorStaticPub, _ := GenerateKey(rand.Reader)
	initiatorEphemeralPriv, initiatorEphemeralPub, _ := GenerateKey(rand.Reader)
	responderStaticPriv, responderStaticPub, _ := GenerateKey(rand.Reader)
	responderEphemeralPriv, responderEphemeralPub, _ := GenerateKey(rand.Reader)

	responderResult, err := CalculateKeyWithConfirmation(false, KeyBits, nil,
		responderStaticPriv, responderEphemeralPriv, responderId,
		initiatorStaticPub, initiatorEphemeralPub, initiatorId)
	if err != nil {
		t.Error(err.Error())
		return
	}

	initiatorResult, err := CalculateKeyWithConfirmation(true, KeyBits, responderResult.S1,
		initiatorStaticPriv, initiatorEphemeralPriv, initiatorId,
		responderStaticPub, responderEphemeralPub, responderId)
	if err != nil {
		t.Error(err.Error())
		return
	}

	if !ResponderConfirm(responderResult.S2, initiatorResult.S2) {
		t.Error("responder confirm s2 failed")
		return
	}
}
