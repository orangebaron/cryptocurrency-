package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

//Curve is the curve used in signatures.
var Curve elliptic.Curve

//User is a user who owns money.
type User struct {
	PublicKey  ecdsa.PublicKey
	CoinsOwned uint64
}

//Transaction is a transfer of coins from one user to another.
type Transaction struct {
	Input            *User
	Output           *User
	CoinsTransferred uint64
	Signature        []byte
}

//Block is a group of transactions in the blockchain.
type Block struct {
	LastBlock    *Block
	Transactions []Transaction
	Miner        *User
	Nonce        uint64
}

//Blockchain is the master list of blocks.
var Blockchain []*Block

func main() {
	Curve = elliptic.P521()
	pkey, _ := ecdsa.GenerateKey(Curve, rand.Reader)
	fmt.Println(pkey.PublicKey)
}
