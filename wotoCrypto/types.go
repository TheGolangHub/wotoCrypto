// wotoCrypto Project
// Copyright (C) 2022 ALiwoto
// This file is subject to the terms and conditions defined in
// file 'LICENSE', which is part of the source code.

package wotoCrypto

import (
	"fmt"

	ws "github.com/AnimeKaizoku/ssg/ssg"
)

type WotoAlgorithm uint16
type WotoLayerLength uint32
type CryptoLayerKind uint8
type blockAction func(first, second singleBlock) singleBlock
type blockAlgorithmId uint8
type KeyLayerCollection []CryptoLayer

type LayerLengthContainer struct {
	Length    WotoLayerLength
	LayerKind CryptoLayerKind
}

type CryptoLayer struct {
	Kind         CryptoLayerKind       `json:"kind"`
	Hash         string                `json:"hash"`
	lenContainer *LayerLengthContainer `json:"-"`
}

type privateBlock rune
type privateCollection struct {
	blocks []privateBlock
}

type blockAlgorithmX917 struct {
	identifier int
}

type blockAlgorithmX847 struct {
	identifier int
}

type blockAlgorithmX795 struct {
	identifier int
}

type blockAlgorithmX649 struct {
	identifier int
}

type AlgorithmSupporter interface {
	SetAlgorithm(algorithm WotoAlgorithm) bool
	HasEqualAlgorithm(algorithm WotoAlgorithm) bool
	GetAlgorithm() WotoAlgorithm
	GetHashCount() int
}

type LayerBlock interface {
	ContainsLayerKind(kind CryptoLayerKind) bool
	ContainsLayer(layer *CryptoLayer) bool
	AppendLayer(layer *CryptoLayer) bool
	RemoveLayer(layer *CryptoLayer) bool
	RemoveLayers(layers ...*CryptoLayer)
	GetLayerLengthByKind(kind CryptoLayerKind) *LayerLengthContainer
	GetLayerLengthByIndex(index int) *LayerLengthContainer
	GetKeyLayersCount() int
}

type WotoKey interface {
	fmt.Stringer
	ws.Validator
	ws.SignatureContainer
	ws.Serializer
	AlgorithmSupporter
	LayerBlock

	IsFuture() bool
	IsPast() bool
	IsPresent() bool
	IsEmpty() bool
	CanBecomeFuture() bool
	CanBecomePresent() bool
	CanBecomePast() bool
	Decrypt(data []byte) []byte
	Encrypt(data []byte) []byte
	HasEqualKind(key WotoKey) bool
	HasEqualSignature(key WotoKey) bool
	GetKeyLength() int
	GetSignatureRealLength() int
	IsRealLengthInvalid() bool

	// Deprecated: you can't convert any WotoKey to a FutureKey anymore.
	// Please use GenerateFutureKey helper function.
	ToFutureKey() WotoKey
	ToPresentKey() WotoKey
	ToPastKey() WotoKey
	Clone() WotoKey

	getLayers() KeyLayerCollection
	setLayers(layers KeyLayerCollection) bool
}

type KeyCollection interface {
	ws.Validator

	ContinueLifeCycle()
	Sync()
}

type KeysContainer interface {
	SetAsKeys(value KeyCollection)
}

type singleBlock interface {
	ws.Validator
	ws.BitsBlocks

	IsEmpty() bool
	IsNonZero() bool
	ToInt64() int64
	ToUInt64() uint64
	ToInt32() int32
	ToUInt32() uint32
	Sum(singleBlock) singleBlock
	Min(singleBlock) singleBlock
	Mul(singleBlock) singleBlock
	Div(singleBlock) singleBlock
}

type blockCollection interface {
	ws.BytesObject

	GetBlocks() []singleBlock
	GetRelativeIndex(int) int
	BlockSize() int
	AppendBlock(singleBlock)
	AppendCollection(blockCollection)
	GetBlockByIndex(int) singleBlock
	Clone() blockCollection
}

type blockAlgorithm interface {
	GetEncryptBlockAction(index int) blockAction
	GetDecryptBlockAction(index int) blockAction
}

type futureKey struct {
	keyLayers KeyLayerCollection
	algorithm WotoAlgorithm
	sig       string
}

type presentKey struct {
	keyLayers KeyLayerCollection
	algorithm WotoAlgorithm
	sig       string
}

type pastKey struct {
	keyLayers KeyLayerCollection
	algorithm WotoAlgorithm
	sig       string
}
