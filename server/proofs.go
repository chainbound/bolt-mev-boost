package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	fastSsz "github.com/ferranbt/fastssz"

	"github.com/attestantio/go-builder-client/api/deneb"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	consensusSpec "github.com/attestantio/go-eth2-client/spec"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// VersionSignedBuilderBidWithProofs is a wrapper struct over `builderSpec.VersionedSignedBuilderBid`
// to include constraint inclusion proofs
type VersionedSignedBuilderBidWithProofs struct {
	Proofs *InclusionProof `json:"proofs,omitempty"`
	*builderSpec.VersionedSignedBuilderBid
}

// Custom MarshalJSON implementation according to Constraints-API.
// Reference: https://docs.boltprotocol.xyz/technical-docs/api/builder#get_header_with_proofs
func (v *VersionedSignedBuilderBidWithProofs) MarshalJSON() ([]byte, error) {
	switch v.Version {
	case consensusSpec.DataVersionDeneb:
		return json.Marshal(struct {
			Message   *deneb.BuilderBid   `json:"message"`
			Signature phase0.BLSSignature `json:"signature"`
			Proofs    *InclusionProof     `json:"proofs"`
		}{
			Message:   v.Deneb.Message,
			Signature: v.Deneb.Signature,
			Proofs:    v.Proofs,
		})
	default:
		return nil, fmt.Errorf("unknown or unsupported data version %d", v.Version)
	}
}

// Custom UnmarshalJSON implementation according to Constraints-API. This is
// needed in order to be spec compliant and without re-implementing the
// underlying consensus types from scratch. Reference:
// https://docs.boltprotocol.xyz/technical-docs/api/builder#get_header_with_proofs
func (v *VersionedSignedBuilderBidWithProofs) UnmarshalJSON(data []byte) error {
	var err error

	var partialBid struct {
		Version consensusSpec.DataVersion `json:"version"`
		// No `Data` field yet, because we need a workaround to add the `Proofs` field in it
	}

	err = json.Unmarshal(data, &partialBid)
	if err != nil {
		return err
	}

	switch partialBid.Version {
	case consensusSpec.DataVersionDeneb:
		var dataBid struct {
			Data struct {
				Message   *deneb.BuilderBid   `json:"message"`
				Signature phase0.BLSSignature `json:"signature"`
				Proofs    *InclusionProof     `json:"proofs"`
			} `json:"data"`
		}

		err = json.Unmarshal(data, &dataBid)
		if err != nil {
			return err
		}

		v.VersionedSignedBuilderBid = &builderSpec.VersionedSignedBuilderBid{
			Version: partialBid.Version,
			Deneb:   &deneb.SignedBuilderBid{Message: dataBid.Data.Message, Signature: dataBid.Data.Signature},
		}

		v.Proofs = dataBid.Data.Proofs

		return nil
	default:
		return fmt.Errorf(
			"failed to unmarshal VersionedSignedBuilderBidWithProofs: unknown or unsupported data version %s",
			partialBid.Version,
		)
	}
}

func (v *VersionedSignedBuilderBidWithProofs) String() string {
	return JSONStringify(v)
}

func (p *InclusionProof) String() string {
	proofs, err := json.Marshal(p)
	if err != nil {
		return err.Error()
	}
	return string(proofs)
}

type HexBytes []byte

func (h HexBytes) Equal(other HexBytes) bool {
	return bytes.Equal(h, other)
}

// MarshalJSON implements json.Marshaler.
func (h HexBytes) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%#x"`, []byte(h))), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (h *HexBytes) UnmarshalJSON(input []byte) error {
	if len(input) == 0 {
		return errors.New("input missing")
	}

	if !bytes.HasPrefix(input, []byte{'"', '0', 'x'}) {
		return errors.New("invalid prefix")
	}

	if !bytes.HasSuffix(input, []byte{'"'}) {
		return errors.New("invalid suffix")
	}

	var data string
	json.Unmarshal(input, &data)

	res, _ := hex.DecodeString(strings.TrimPrefix(data, "0x"))

	*h = res

	return nil
}

// InclusionProof is a Merkle Multiproof of inclusion of a set of TransactionHashes
type InclusionProof struct {
	TransactionHashes  []phase0.Hash32 `json:"transaction_hashes"`
	GeneralizedIndexes []uint64        `json:"generalized_indexes"`
	MerkleHashes       []*HexBytes     `json:"merkle_hashes"`
}

// InclusionProofFromMultiProof converts a fastssz.Multiproof into an InclusionProof, without
// filling the TransactionHashes
func InclusionProofFromMultiProof(mp *fastSsz.Multiproof) *InclusionProof {
	merkleHashes := make([]*HexBytes, len(mp.Hashes))
	for i, h := range mp.Hashes {
		merkleHashes[i] = new(HexBytes)
		*(merkleHashes[i]) = h
	}

	leaves := make([]*HexBytes, len(mp.Leaves))
	for i, h := range mp.Leaves {
		leaves[i] = new(HexBytes)
		*(leaves[i]) = h
	}
	generalIndexes := make([]uint64, len(mp.Indices))
	for i, idx := range mp.Indices {
		generalIndexes[i] = uint64(idx)
	}
	return &InclusionProof{
		MerkleHashes:       merkleHashes,
		GeneralizedIndexes: generalIndexes,
	}
}
