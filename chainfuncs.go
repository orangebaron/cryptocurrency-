package cryptocurrency

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json" //TODO: don't use json
)

//TODO: all of the maps here are pointer maps, so clear them when you're done

//BytesObject can be converted to a byte slice.
type BytesObject interface {
	GetBytes() []byte
	GetHash() []byte
}

func getHash(obj BytesObject) []byte {
	_, checked := hashes[&obj]
	if checked {
		return hashes[&obj]
	}
	hash := sha256.New()
	hash.Write(obj.GetBytes())
	sum := hash.Sum(nil)
	hashes[&obj] = sum
	return sum
}

//GetHash returns a transaction's hash.
func (t *Transaction) GetHash() []byte {
	return getHash(t)
}

//GetHash returns a block's hash.
func (b *Block) GetHash() []byte {
	return getHash(b)
}

var generatedBytes map[interface{}][]byte

//GetBytes converts a transaction into bytes.
func (t *Transaction) GetBytes() []byte {
	bytes, checked := generatedBytes[t]
	if checked {
		return bytes
	}

	marshalBlock := struct {
		Inputs []struct {
			Input     []byte
			OutputNum uint8
		}
		Outputs []struct {
			Key              *ecdsa.PublicKey
			CoinsTransferred uint64
		}
	}{
		make([]struct {
			Input     []byte
			OutputNum uint8
		}, len(t.Inputs)),
		t.Outputs,
	}
	for i, inp := range t.Inputs {
		marshalBlock.Inputs[i].Input = inp.Input.GetBytes()
		marshalBlock.Inputs[i].OutputNum = inp.OutputNum
	}
	bytes, _ = json.Marshal(marshalBlock)
	generatedBytes[t] = bytes
	return bytes
}

//GetBytes converts a block into bytes.
func (b *Block) GetBytes() []byte {
	bytes, checked := generatedBytes[b]
	if checked {
		return bytes
	}

	marshalBlock := struct {
		PrevHash     []byte
		Transactions []Transaction
		Miner        *ecdsa.PublicKey
		Nonce        uint64
	}{b.PrevBlock.GetHash(), b.Transactions, b.Miner, b.Nonce}
	bytes, _ = json.Marshal(marshalBlock)
	generatedBytes[b] = bytes
	return bytes
}

var hashes map[*BytesObject][]byte

var validities map[interface{}]bool
var spent map[*Transaction]*Transaction

//IsValid checks a signature's validity.
func (s Signature) IsValid(signed BytesObject, signer *ecdsa.PublicKey) bool {
	return ecdsa.Verify(signer, signed.GetHash(), R, S)
}

//IsValid checks a transaction's validity.
func (t *Transaction) IsValid() bool {
	v, checked := validities[t]
	if checked {
		return v
	}
	validities[t] = false

	var inpMoney, otpMoney uint64
	for _, inp := range t.Inputs {
		if !inp.Input.IsValid() {
			return false
		}
		if spent[inp.Input] != nil && spent[inp.Input] != t {
			return false
		}
		inpMoney += inp.Input.Outputs[inp.OutputNum].CoinsTransferred
	}
	for _, otp := range t.Outputs {
		otpMoney += otp.CoinsTransferred
	}
	if inpMoney != otpMoney {
		return false
	}

	if len(t.Inputs) != len(t.Signatures) {
		return false
	}
	for i, sig := range t.Signatures {
		if !sig.IsValid(t, t.Inputs[i].Input.Outputs[t.Inputs[i].OutputNum].Key) {
			return false
		}
	}

	validities[t] = true
	return true
}
func (t *Transaction) markInputsAsSpent() {
	for _, inp := range t.Inputs {
		spent[inp.Input] = t
	}
}
func (t *Transaction) markInputsAsUnspent() {
	for _, inp := range t.Inputs {
		spent[inp.Input] = nil
	}
}

//IsValid checks a block's validity.
func (b *Block) IsValid() bool {
	v, checked := validities[b]
	if checked {
		return v
	}
	validities[b] = false
	if !b.PrevBlock.IsValid() {
		return false
	}
	for _, t := range b.Transactions {
		if !t.IsValid() {
			return false
		}
	}

	for _, t := range b.Transactions {
		t.markInputsAsSpent()
	}
	validities[b] = true
	return true
}
