/*

 */

package hdwallet

import (
	"crypto/elliptic"
	"github.com/btcsuite/btcd/btcec"
)

func (w *Wallet) GetBTCExternalKeyPair(i uint32) (*btcec.PrivateKey, *btcec.PublicKey, error) {

	key, err := w.btcPrivKey(i, externalChain)
	if err != nil {
		return nil, nil, err
	}

	privKey, pubkey := btcec.PrivKeyFromBytes(elliptic.P256(), key.key)
	return privKey, pubkey, nil
}


func (w *Wallet) GetBTCChangeKeyPair(i uint32) (*btcec.PrivateKey, *btcec.PublicKey, error) {

	key, err := w.btcPrivKey(i, internalChain)
	if err != nil {
		return nil, nil, err
	}

	privKey, pubkey := btcec.PrivKeyFromBytes(elliptic.P256(), key.key)
	return privKey, pubkey, nil
}



func (w *Wallet) btcPrivKey(i uint32, ct changeType) (*ExtendedKey, error) {

	gen := &Secp256K1{}

	master := MasterKeyGenerate(w.Seed, Secp256k1CurvePhrase)

	purposeKey, err := gen.Child(*master, hardenIndex(purposeBIP44))
	if err != nil {
		return nil, err
	}

	btcKey, err := gen.Child(*purposeKey, hardenIndex(coinTypeBTC))
	if err != nil {
		return nil, err
	}

	accountKey, err := gen.Child(*btcKey, hardenIndex(0))
	if err != nil {
		return nil, err
	}

	changeKey, err := gen.Child(*accountKey, uint32(ct))
	if err != nil {
		return nil, err
	}

	indexKey, err := gen.Child(*changeKey, i)
	if err != nil {
		return nil, err
	}

	return indexKey, nil
}