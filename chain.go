package cryptocurrency

import (
	"crypto/ecdsa"
	"crypto/elliptic"
)

//Curve is the curve used in signatures.
var Curve = elliptic.P521()

//Transaction is a transfer of coins from one user to another.
type Transaction struct {
	Inputs           []*Transaction
	Output           *ecdsa.PublicKey
	CoinsTransferred uint64
	Signatures       [][]byte
}

//Block is a group of transactions in the blockchain.
type Block struct {
	PrevBlock    *Block
	Transactions []Transaction
	Miner        *ecdsa.PublicKey
	Nonce        uint64
}
