package cryptocurrency

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

//R is the R value used for signatures.
var R = big.NewInt(65)

//S is the S value used for signatures.
var S = big.NewInt(65)

//Signature is a cryptographic signature.
type Signature []byte

//Curve is the curve used in signatures.
var Curve = elliptic.P521()

//Transaction is a transfer of coins from one user to another.
type Transaction struct {
	Inputs []struct {
		Input     *Transaction
		OutputNum uint8
	}
	Outputs []struct {
		Key              *ecdsa.PublicKey
		CoinsTransferred uint64
	}
	Signatures []Signature
}

//Block is a group of transactions in the blockchain.
type Block struct {
	PrevBlock    *Block
	Transactions []Transaction
	Miner        *ecdsa.PublicKey
	Nonce        uint64
}
