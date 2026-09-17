package xcrypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// DH is the static description of one Diffie-Hellman group.
type DH struct {
	TransformID uint16
	Name        string
}

// DHKey is one ephemeral private key for a DH exchange. The underlying
// key is fixed after construction; the struct is not safe for
// concurrent use (each handshake owns one).
type DHKey struct {
	dh      DH
	key     *ecdh.PrivateKey
	modpX   *big.Int
	modpP   *big.Int
	modpLen int
	modpPub []byte
}

var (
	bigOne = big.NewInt(1)
	bigTwo = big.NewInt(2)

	modp1024P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
	modp2048P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
)

// NewDH creates one static DH group descriptor.
func NewDH(group uint16) (*DH, error) {
	switch group {
	case TransformDHCurve25519:
		return &DH{TransformID: group, Name: "curve25519"}, nil
	case TransformDHMODP1024:
		return &DH{TransformID: group, Name: "modp1024"}, nil
	case TransformDHMODP2048:
		return &DH{TransformID: group, Name: "modp2048"}, nil
	default:
		return nil, fmt.Errorf("xcrypto: unsupported DH group %d", group)
	}
}

func newDH(group uint16) (*DH, error) {
	return NewDH(group)
}

// GenerateDH creates one ephemeral keypair for the group.
func GenerateDH(group uint16) (*DHKey, error) {
	dh, err := newDH(group)
	if err != nil {
		return nil, err
	}
	switch group {
	case TransformDHCurve25519:
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("xcrypto: generate X25519 keypair: %w", err)
		}
		return &DHKey{dh: *dh, key: key}, nil
	case TransformDHMODP1024:
		return generateMODP(*dh, modp1024P, 128)
	case TransformDHMODP2048:
		return generateMODP(*dh, modp2048P, 256)
	default:
		return nil, fmt.Errorf("xcrypto: unsupported DH group %d", group)
	}
}

func generateMODP(dh DH, prime *big.Int, byteLen int) (*DHKey, error) {
	// Private key x: 2 <= x <= prime - 2
	max := new(big.Int).Sub(prime, bigTwo)
	x, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("xcrypto: generate MODP private key: %w", err)
	}
	x.Add(x, bigTwo)

	// Public key: g^x mod prime, g = 2
	pub := new(big.Int).Exp(bigTwo, x, prime)
	pubBytes := make([]byte, byteLen)
	pub.FillBytes(pubBytes)

	return &DHKey{
		dh:      dh,
		modpX:   x,
		modpP:   prime,
		modpLen: byteLen,
		modpPub: pubBytes,
	}, nil
}

// Group reports the negotiated group id.
func (k *DHKey) Group() uint16 {
	return k.dh.TransformID
}

// PublicBytes returns the public key for the KE payload.
func (k *DHKey) PublicBytes() ([]byte, error) {
	if k.key == nil && k.modpX == nil {
		return nil, errors.New("xcrypto: DH private key already consumed")
	}
	if k.key != nil {
		return k.key.PublicKey().Bytes(), nil
	}
	return append([]byte(nil), k.modpPub...), nil
}

// ECDH derives the shared secret and takes the private key out of play:
// the secret is zeroized after the SKEYSEED derivation has consumed it.
func (k *DHKey) ECDH(peer []byte) ([]byte, error) {
	if k.key == nil && k.modpX == nil {
		return nil, errors.New("xcrypto: DH private key already consumed")
	}
	if k.key != nil {
		if len(peer) != 32 {
			return nil, fmt.Errorf("xcrypto: invalid X25519 peer public key length %d", len(peer))
		}
		pub, err := ecdh.X25519().NewPublicKey(peer)
		if err != nil {
			return nil, fmt.Errorf("xcrypto: parse X25519 peer public key: %w", err)
		}
		secret, err := k.key.ECDH(pub)
		if err != nil {
			return nil, fmt.Errorf("xcrypto: derive X25519 shared secret: %w", err)
		}
		k.key = nil
		return secret, nil
	}

	// MODP derivation
	if len(peer) != k.modpLen {
		return nil, fmt.Errorf("xcrypto: invalid MODP peer public key length %d, expected %d", len(peer), k.modpLen)
	}
	peerInt := new(big.Int).SetBytes(peer)
	pMinus1 := new(big.Int).Sub(k.modpP, bigOne)
	if peerInt.Cmp(bigOne) <= 0 || peerInt.Cmp(pMinus1) >= 0 {
		return nil, fmt.Errorf("xcrypto: MODP peer public key out of range (1 < pub < p-1)")
	}

	secret := new(big.Int).Exp(peerInt, k.modpX, k.modpP)
	secretBytes := make([]byte, k.modpLen)
	secret.FillBytes(secretBytes)

	// Zeroize private key
	k.modpX.SetInt64(0)
	k.modpX = nil
	k.modpPub = nil

	return secretBytes, nil
}
