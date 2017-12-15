package cryptocurrency

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
)

//BytesObject can be converted to a byte slice.
type BytesObject interface {
	GetBytes() []byte
}

//GetBytes converts a block into bytes.
func (b *Block) GetBytes() []byte { //TODO: don't use json
	marshalBlock := struct {
		PrevHash     []byte
		Transactions []Transaction
		Miner        *ecdsa.PublicKey
		Nonce        uint64
	}{GetHash(b.PrevBlock), b.Transactions, b.Miner, b.Nonce}
	bytes, _ := json.Marshal(marshalBlock)
	return bytes
}

//GetHash returns a block's hash.
func GetHash(obj BytesObject) []byte {
	hash := sha256.New()
	hash.Write(obj.GetBytes())
	return hash.Sum(nil)
}

var validityChecked map[*Block]bool
var validity map[*Block]bool

//IsValid checks a block's validity.
func (b *Block) IsValid() bool {
	if validityChecked[b] {
		return validity[b]
	}
	return true //TODO: yES,
}
