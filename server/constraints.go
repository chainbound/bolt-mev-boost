package server

import (
	"errors"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	gethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	lru "github.com/hashicorp/golang-lru/v2"
)

type (
	BatchedSignedConstraints = []*SignedConstraints
	HashToTransactionDecoded = map[gethCommon.Hash]*types.Transaction
)

// SignedConstraints represents the signed constraints.
// Reference: https://docs.boltprotocol.xyz/api/builder
type SignedConstraints struct {
	Message   ConstraintsMessage  `json:"message"`
	Signature phase0.BLSSignature `json:"signature"`
}

// ConstraintsMessage represents the constraints message.
// Reference: https://docs.boltprotocol.xyz/api/builder
type ConstraintsMessage struct {
	Pubkey       phase0.BLSPubKey  `json:"pubkey"`
	Slot         uint64            `json:"slot"`
	Top          bool              `json:"top"`
	Transactions []*HexTransaction `json:"transactions"`
}

func (s *SignedConstraints) String() string {
	return JSONStringify(s)
}

func (m *ConstraintsMessage) String() string {
	return JSONStringify(m)
}

// TransactionHashMap is a map of transaction hashes to transactions that have
// been marshalled without the blob sidecar.
type TransactionHashMap = map[gethCommon.Hash]*HexTransaction

// ConstraintsCache is a cache for constraints.
type ConstraintsCache struct {
	// map of slots to all constraints for that slot
	constraints *lru.Cache[uint64, TransactionHashMap]
}

// NewConstraintsCache creates a new constraint cache.
// cap is the maximum number of slots to store constraints for.
func NewConstraintsCache(cap int) *ConstraintsCache {
	constraints, _ := lru.New[uint64, TransactionHashMap](cap)
	return &ConstraintsCache{
		constraints: constraints,
	}
}

// AddInclusionConstraints adds multiple inclusion constraints to the cache at the given slot
func (c *ConstraintsCache) AddInclusionConstraints(slot uint64, transactions []*HexTransaction) error {
	if len(transactions) == 0 {
		return nil
	}

	m, exists := c.constraints.Get(slot)
	if !exists {
		c.constraints.Add(slot, make(TransactionHashMap))
	}

	for _, txRaw := range transactions {
		if txRaw == nil {
			return errors.New("cannot add nil transaction")
		}

		txDecoded := new(types.Transaction)
		err := txDecoded.UnmarshalBinary(*txRaw)
		if err != nil {
			return err
		}

		txDecoded = txDecoded.WithoutBlobTxSidecar()
		txWithoutblobSidecarRaw, err := txDecoded.MarshalBinary()
		if err != nil {
			return err
		}
		hex := HexTransaction(txWithoutblobSidecarRaw)

		m[txDecoded.Hash()] = &hex
	}

	return nil
}

// Get gets the constraints at the given slot.
func (c *ConstraintsCache) Get(slot uint64) (TransactionHashMap, bool) {
	return c.constraints.Get(slot)
}

// FindTransactionByHash finds the constraint for the given transaction hash and returns it.
func (c *ConstraintsCache) FindTransactionByHash(txHash gethCommon.Hash) (*HexTransaction, bool) {
	for _, hashToTx := range c.constraints.Values() {
		if tx, exists := hashToTx[txHash]; exists {
			return tx, true
		}
	}
	return nil, false
}

// SignedDelegation represents the delegation signed by the proposer pubkey to
// authorize the delegatee pubkey to submit constraints on their behalf.
//
// Specs: https://docs.boltprotocol.xyz/api/builder#delegate
type SignedDelegation struct {
	Message   Delegation          `json:"message"`
	Signature phase0.BLSSignature `json:"signature"`
}

func (s *SignedDelegation) String() string {
	return JSONStringifyPretty(s)
}

// Delegation as from Specs: https://docs.boltprotocol.xyz/api/builder#delegate
type Delegation struct {
	Action          uint8            `json:"action"`
	ValidatorPubkey phase0.BLSPubKey `json:"validator_pubkey"`
	DelegateePubkey phase0.BLSPubKey `json:"delegatee_pubkey"`
}

// SignedRevocation represents the revocation signed by the proposer pubkey to
// revoke the delegatee pubkey's ability to submit constraints on their behalf.
//
// Specs: https://docs.boltprotocol.xyz/api/builder#revoke
type SignedRevocation struct {
	Message   Revocation          `json:"message"`
	Signature phase0.BLSSignature `json:"signature"`
}

// Revocation as from Specs: https://docs.boltprotocol.xyz/api/builder#revoke
type Revocation struct {
	Action          uint8            `json:"action"`
	ValidatorPubkey phase0.BLSPubKey `json:"validator_pubkey"`
	DelegateePubkey phase0.BLSPubKey `json:"delegatee_pubkey"`
}
