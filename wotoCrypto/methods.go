// wotoCrypto Project
// Copyright (C) 2022 ALiwoto
// This file is subject to the terms and conditions defined in
// file 'LICENSE', which is part of the source code.

package wotoCrypto

/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "woto_bindings/common_helpers.c"
*/
import "C"

import (
	"encoding/json"
	"hash"
	"strconv"
	"unsafe"
)

//---------------------------------------------------------

func (c *LayerLengthContainer) IsValid() bool {
	return c != nil && layerKindsMap[c.LayerKind] && c.isLengthValid()
}

func (c *LayerLengthContainer) isLengthValid() bool {
	return layerLengthValidator[c.LayerKind](c.Length)
}

//---------------------------------------------------------

func (l *CryptoLayer) GetLayerLength() *LayerLengthContainer {
	if l == nil {
		return nil
	}

	if l.lenContainer.IsValid() {
		return l.lenContainer
	}

	l.lenContainer = l.getNewLayerContainer()

	return l.lenContainer
}

func (l *CryptoLayer) IsValid() bool {
	return l.GetLayerLength().IsValid()
}

func (l *CryptoLayer) ToBytes() []byte {
	if !l.IsValid() {
		return nil
	}

	return []byte(l.Hash)
}

func (l *CryptoLayer) getNewLayerContainer() *LayerLengthContainer {
	return &LayerLengthContainer{
		Length:    l.getLength(),
		LayerKind: l.Kind,
	}
}

func (l *CryptoLayer) getLength() WotoLayerLength {
	return WotoLayerLength(len(l.Hash))
}

func (l *CryptoLayer) Equal(layer *CryptoLayer) bool {
	return l.Hash == layer.Hash && l.Kind == layer.Kind
}

//---------------------------------------------------------

func (c KeyLayerCollection) GetLayerByIndex(index int) *CryptoLayer {
	if index >= len(c) {
		return nil
	}

	return &c[index]
}

func (c KeyLayerCollection) IsValid() bool {
	return len(c) != 0 && c.validateKeys()
}

func (c KeyLayerCollection) Contains(layer *CryptoLayer) bool {
	for _, current := range c {
		if current.Equal(layer) {
			return true
		}
	}

	return false
}

func (c KeyLayerCollection) ContainsKind(kind CryptoLayerKind) bool {
	for _, current := range c {
		if current.Kind == kind {
			return true
		}
	}

	return false
}

func (c KeyLayerCollection) GetKeyLength() int {
	var total int
	for _, current := range c {
		total += int(current.getLength())
	}

	return total
}

func (c KeyLayerCollection) validateKeys() bool {
	for _, current := range c {
		if !current.IsValid() {
			return false
		}
	}

	return false
}

func (c KeyLayerCollection) GetLayerLengthByKind(kind CryptoLayerKind) *LayerLengthContainer {
	for _, current := range c {
		if current.Kind == kind {
			return current.GetLayerLength()
		}
	}

	return nil
}

//---------------------------------------------------------

func (p *presentKey) GetLayers() KeyLayerCollection {
	return p.keyLayers
}

func (p *presentKey) GetLayerLengthByIndex(index int) *LayerLengthContainer {
	return p.keyLayers.GetLayerByIndex(index).GetLayerLength()
}

func (p *presentKey) SetLayers(layers KeyLayerCollection) bool {
	if !layers.IsValid() || !p.isValidWithAlgo(layers) {
		return false
	}

	p.keyLayers = layers

	return true
}

func (p *presentKey) isValidWithAlgo(layers KeyLayerCollection) bool {
	return true
}

func (p *presentKey) SetAlgorithm(algorithm WotoAlgorithm) bool {
	p.algorithm = algorithm
	return true
}

func (p *presentKey) GetSignature() string {
	return p.sig
}

func (p *presentKey) IsValid() bool {
	return p != nil && !p.IsEmpty() && p.sig != ""
}

func (p *presentKey) IsEmpty() bool {
	return len(p.keyLayers) == 0x0
}

func (p *presentKey) SetSignature(signature string) bool {
	if signature == "" {
		return false
	}

	p.sig = signature
	return true
}

func (p *presentKey) SetSignatureByBytes(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	return p.SetSignature(string(data))
}

func (p *presentKey) SetSignatureByFunc(h func() hash.Hash) bool {
	if h == nil {
		return false
	}
	return p.SetSignatureByBytes(h().Sum(nil))
}

func (p *presentKey) Encrypt(data []byte) []byte {
	if !p.IsValid() {
		return data
	}

	switch p.algorithm {
	case WotoAlgorithmM250:
		return p.encryptM250(data)
	}
	return nil
}

func (p *presentKey) Serialize() ([]byte, error) {
	if !p.IsValid() {
		return nil, ErrInvalidKey
	}

	b, err := json.Marshal(p.toMap())
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (p *presentKey) StrSerialize() string {
	b, err := p.Serialize()
	if err != nil || len(b) == 0 {
		return ""
	}

	return string(b)
}

func (p *presentKey) toMap() map[string]interface{} {
	return map[string]interface{}{
		"key_layers": p.keyLayers,
		"signature":  p.sig,
		"algorithm":  p.algorithm,
	}
}

func (p *presentKey) Decrypt(data []byte) []byte {
	if !p.IsValid() {
		return data
	}

	switch p.algorithm {
	case WotoAlgorithmM250:
		return p.decryptM250(data)
	}
	return nil
}

func (p *presentKey) encryptM250(data []byte) []byte {
	var currentKey []byte
	currentKey = p.keyLayers[0x0].ToBytes()
	for i, currentLayer := range p.keyLayers {
		if i == 0x0 {
			continue
		}
		currentKey = EncryptData(currentKey, currentLayer.ToBytes())
	}

	return EncryptData(currentKey, data)
}

func (p *presentKey) decryptM250(data []byte) []byte {
	var currentKey []byte
	currentKey = p.keyLayers[0x0].ToBytes()
	for i, currentLayer := range p.keyLayers {
		if i == 0x0 {
			continue
		}
		currentKey = EncryptData(currentKey, currentLayer.ToBytes())
	}

	return DecryptData(currentKey, data)
}

func (p *presentKey) AppendLayer(layer *CryptoLayer) bool {
	if !layer.IsValid() {
		return false
	}

	p.keyLayers = append(p.keyLayers, *layer)
	return true
}

func (p *presentKey) RemoveLayer(layer *CryptoLayer) bool {
	var newLayers KeyLayerCollection
	var done bool
	for _, current := range p.keyLayers {
		if !done && current.Equal(layer) {
			continue
		}
		newLayers = append(newLayers, current)
	}

	p.keyLayers = newLayers
	return true
}

func (p *presentKey) CanBecomeFuture() bool {
	return false
}

func (p *presentKey) CanBecomePast() bool {
	return p.algorithm&0x25 != 0x78
}

func (p *presentKey) CanBecomePresent() bool {
	return true
}

func (p *presentKey) ContainsLayer(layer *CryptoLayer) bool {
	if len(p.keyLayers) == 0x0 {
		return false
	}
	return p.keyLayers.Contains(layer)
}

func (p *presentKey) ContainsLayerKind(kind CryptoLayerKind) bool {
	if len(p.keyLayers) == 0x0 {
		return false
	}
	return p.keyLayers.ContainsKind(kind)
}

func (p *presentKey) GetAlgorithm() WotoAlgorithm {
	return p.algorithm
}

func (p *presentKey) GetHashCount() int {
	return len(p.keyLayers)
}

func (p *presentKey) GetKeyLayersCount() int {
	return len(p.keyLayers)
}

func (p *presentKey) GetKeyLength() int {
	if len(p.keyLayers) == 0x0 {
		return 0x0
	}
	return p.keyLayers.GetKeyLength()
}

func (p *presentKey) GetLayerLengthByKind(kind CryptoLayerKind) *LayerLengthContainer {
	if len(p.keyLayers) == 0x0 {
		return nil
	}
	return p.keyLayers.GetLayerLengthByKind(kind)
}

func (p *presentKey) HasEqualAlgorithm(algorithm WotoAlgorithm) bool {
	return p.algorithm == algorithm
}

func (p *presentKey) HasEqualKind(key WotoKey) bool {
	return key.IsPresent()
}

func (p *presentKey) HasEqualSignature(key WotoKey) bool {
	return p.sig == key.GetSignature()
}

func (p *presentKey) IsFuture() bool {
	return false
}

func (p *presentKey) IsPast() bool {
	return false
}

func (p *presentKey) IsPresent() bool {
	return true
}

func (p *presentKey) RemoveLayers(layers ...*CryptoLayer) {
	for _, layer := range layers {
		p.RemoveLayer(layer)
	}
}

func (p *presentKey) GetSignatureRealLength() int {
	if p.sig == "" {
		return 0x0
	}
	myStr := C.CString(p.sig)
	defer C.free(unsafe.Pointer(myStr))
	return int(C.compute_signature_real_length(myStr, C.int(p.algorithm)))
}

func (p *presentKey) ToFutureKey() WotoKey {
	return &futureKey{
		keyLayers: p.keyLayers,
		algorithm: p.algorithm,
		sig:       p.sig,
	}
}

func (p *presentKey) Clone() WotoKey {
	return &presentKey{
		keyLayers: p.keyLayers,
		algorithm: p.algorithm,
		sig:       p.sig,
	}
}

func (p *presentKey) ToPastKey() WotoKey {
	return &pastKey{
		keyLayers: p.keyLayers,
		algorithm: p.algorithm,
		sig:       p.sig,
	}
}

func (p *presentKey) ToPresentKey() WotoKey {
	return p
}

func (p *presentKey) getLayers() KeyLayerCollection {
	return p.keyLayers
}

func (p *presentKey) setLayers(layers KeyLayerCollection) bool {
	p.keyLayers = layers
	return true
}

//---------------------------------------------------------

func (f *futureKey) GetLayers() KeyLayerCollection {
	return f.keyLayers
}

func (f *futureKey) GetLayerLengthByIndex(index int) *LayerLengthContainer {
	return f.keyLayers.GetLayerByIndex(index).GetLayerLength()
}

func (f *futureKey) SetLayers(layers KeyLayerCollection) bool {
	if !layers.IsValid() || !f.isValidWithAlgo(layers) {
		return false
	}

	f.keyLayers = layers

	return true
}

func (f *futureKey) isValidWithAlgo(layers KeyLayerCollection) bool {
	return true
}

func (f *futureKey) SetAlgorithm(algorithm WotoAlgorithm) bool {
	f.algorithm = algorithm
	return true
}

func (f *futureKey) AppendLayer(layer *CryptoLayer) bool {
	if !layer.IsValid() {
		return false
	}

	f.keyLayers = append(f.keyLayers, *layer)
	return true
}

func (f *futureKey) CanBecomeFuture() bool {
	return true
}

func (f *futureKey) CanBecomePast() bool {
	return false
}

func (f *futureKey) CanBecomePresent() bool {
	return f.algorithm&0x25 != 0x78
}

func (f *futureKey) ContainsLayer(layer *CryptoLayer) bool {
	if len(f.keyLayers) == 0x0 {
		return false
	}
	return f.keyLayers.Contains(layer)
}

func (f *futureKey) ContainsLayerKind(kind CryptoLayerKind) bool {
	if len(f.keyLayers) == 0x0 {
		return false
	}
	return f.keyLayers.ContainsKind(kind)
}

func (f *futureKey) GetAlgorithm() WotoAlgorithm {
	return f.algorithm
}

func (f *futureKey) GetHashCount() int {
	return len(f.keyLayers)
}

func (f *futureKey) GetKeyLayersCount() int {
	return len(f.keyLayers)
}

func (f *futureKey) GetKeyLength() int {
	if len(f.keyLayers) == 0x0 {
		return 0x0
	}
	return f.keyLayers.GetKeyLength()
}

func (f *futureKey) GetLayerLengthByKind(kind CryptoLayerKind) *LayerLengthContainer {
	if len(f.keyLayers) == 0x0 {
		return nil
	}
	return f.keyLayers.GetLayerLengthByKind(kind)
}

func (f *futureKey) HasEqualAlgorithm(algorithm WotoAlgorithm) bool {
	return f.algorithm == algorithm
}

func (f *futureKey) HasEqualKind(key WotoKey) bool {
	return key.IsFuture()
}

func (f *futureKey) HasEqualSignature(key WotoKey) bool {
	return f.sig == key.GetSignature()
}

func (f *futureKey) IsFuture() bool {
	return true
}

func (f *futureKey) IsPast() bool {
	return false
}

func (f *futureKey) IsPresent() bool {
	return false
}

func (f *futureKey) RemoveLayers(layers ...*CryptoLayer) {
	for _, layer := range layers {
		f.RemoveLayer(layer)
	}
}

func (f *futureKey) RemoveLayer(layer *CryptoLayer) bool {
	var newLayers KeyLayerCollection
	var done bool
	for _, current := range f.keyLayers {
		if !done && current.Equal(layer) {
			continue
		}
		newLayers = append(newLayers, current)
	}

	f.keyLayers = newLayers
	return true
}

func (f *futureKey) Decrypt(data []byte) []byte {
	return nil
}

func (f *futureKey) Encrypt(data []byte) []byte {
	return nil
}

func (f *futureKey) GetSignature() string {
	return f.sig
}

func (f *futureKey) IsEmpty() bool {
	return len(f.keyLayers) == 0x0
}

func (f *futureKey) IsValid() bool {
	return f != nil && !f.IsEmpty() && f.sig != ""
}

func (f *futureKey) Serialize() ([]byte, error) {
	if !f.IsValid() {
		return nil, ErrInvalidKey
	}

	b, err := json.Marshal(f.toMap())
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (f *futureKey) StrSerialize() string {
	b, err := f.Serialize()
	if err != nil || len(b) == 0 {
		return ""
	}

	return string(b)
}

func (f *futureKey) toMap() map[string]interface{} {
	return map[string]interface{}{
		"key_layers": f.keyLayers,
		"signature":  f.sig,
		"algorithm":  f.algorithm,
	}
}

func (f *futureKey) SetSignature(signature string) bool {
	if signature == "" {
		return false
	}

	f.sig = signature
	return true
}

func (f *futureKey) SetSignatureByBytes(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	return f.SetSignature(string(data))
}

func (f *futureKey) SetSignatureByFunc(h func() hash.Hash) bool {
	if h == nil {
		return false
	}
	return f.SetSignatureByBytes(h().Sum(nil))
}

func (f *futureKey) GetSignatureRealLength() int {
	if f.sig == "" {
		return 0x0
	}
	myStr := C.CString(f.sig)
	defer C.free(unsafe.Pointer(myStr))
	return int(C.compute_signature_real_length(myStr, C.int(f.algorithm)))
}

func (f *futureKey) ToFutureKey() WotoKey {
	return f
}

func (f *futureKey) ToPastKey() WotoKey {
	return nil
}

func (f *futureKey) ToPresentKey() WotoKey {
	return &presentKey{
		keyLayers: f.keyLayers,
		algorithm: f.algorithm,
		sig:       f.sig,
	}
}

func (f *futureKey) Clone() WotoKey {
	return &futureKey{
		keyLayers: f.keyLayers,
		algorithm: f.algorithm,
		sig:       f.sig,
	}
}

func (f *futureKey) getLayers() KeyLayerCollection {
	return f.keyLayers
}

func (f *futureKey) setLayers(layers KeyLayerCollection) bool {
	f.keyLayers = layers
	return true
}

//---------------------------------------------------------

func (p *pastKey) GetLayers() KeyLayerCollection {
	return p.keyLayers
}

func (p *pastKey) GetLayerLengthByIndex(index int) *LayerLengthContainer {
	return p.keyLayers.GetLayerByIndex(index).GetLayerLength()
}

func (p *pastKey) SetLayers(layers KeyLayerCollection) bool {
	if !layers.IsValid() || !p.isValidWithAlgo(layers) {
		return false
	}

	p.keyLayers = layers

	return true
}

func (p *pastKey) isValidWithAlgo(layers KeyLayerCollection) bool {
	return true
}

func (p *pastKey) SetAlgorithm(algorithm WotoAlgorithm) bool {
	p.algorithm = algorithm
	return true
}

func (p *pastKey) AppendLayer(layer *CryptoLayer) bool {
	if !layer.IsValid() {
		return false
	}

	p.keyLayers = append(p.keyLayers, *layer)
	return true
}

func (p *pastKey) CanBecomeFuture() bool {
	return true
}

func (p *pastKey) CanBecomePast() bool {
	return false
}

func (p *pastKey) CanBecomePresent() bool {
	return false
}

func (p *pastKey) ContainsLayer(layer *CryptoLayer) bool {
	if len(p.keyLayers) == 0x0 {
		return false
	}
	return p.keyLayers.Contains(layer)
}

func (p *pastKey) ContainsLayerKind(kind CryptoLayerKind) bool {
	if len(p.keyLayers) == 0x0 {
		return false
	}
	return p.keyLayers.ContainsKind(kind)
}

func (p *pastKey) GetAlgorithm() WotoAlgorithm {
	return p.algorithm
}

func (p *pastKey) GetHashCount() int {
	return len(p.keyLayers)
}

func (p *pastKey) GetKeyLayersCount() int {
	return len(p.keyLayers)
}

func (p *pastKey) GetKeyLength() int {
	if len(p.keyLayers) == 0x0 {
		return 0x0
	}
	return p.keyLayers.GetKeyLength()
}

func (p *pastKey) GetLayerLengthByKind(kind CryptoLayerKind) *LayerLengthContainer {
	if len(p.keyLayers) == 0x0 {
		return nil
	}
	return p.keyLayers.GetLayerLengthByKind(kind)
}

func (p *pastKey) HasEqualAlgorithm(algorithm WotoAlgorithm) bool {
	return p.algorithm == algorithm
}

func (p *pastKey) HasEqualKind(key WotoKey) bool {
	return key.IsPast()
}

func (p *pastKey) HasEqualSignature(key WotoKey) bool {
	return p.sig == key.GetSignature()
}

func (p *pastKey) IsFuture() bool {
	return true
}

func (p *pastKey) IsPast() bool {
	return false
}

func (p *pastKey) IsPresent() bool {
	return false
}

func (p *pastKey) RemoveLayers(layers ...*CryptoLayer) {
	for _, layer := range layers {
		p.RemoveLayer(layer)
	}
}

func (p *pastKey) RemoveLayer(layer *CryptoLayer) bool {
	var newLayers KeyLayerCollection
	var done bool
	for _, current := range p.keyLayers {
		if !done && current.Equal(layer) {
			continue
		}
		newLayers = append(newLayers, current)
	}

	p.keyLayers = newLayers
	return true
}

func (p *pastKey) Decrypt(data []byte) []byte {
	return nil
}

func (p *pastKey) Encrypt(data []byte) []byte {
	return nil
}

func (p *pastKey) GetSignature() string {
	return p.sig
}

func (p *pastKey) IsEmpty() bool {
	return len(p.keyLayers) == 0x0
}

func (p *pastKey) IsValid() bool {
	return p != nil && !p.IsEmpty() && p.sig != ""
}

func (p *pastKey) Serialize() ([]byte, error) {
	if !p.IsValid() {
		return nil, ErrInvalidKey
	}

	b, err := json.Marshal(p.toMap())
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (p *pastKey) StrSerialize() string {
	b, err := p.Serialize()
	if err != nil || len(b) == 0 {
		return ""
	}

	return string(b)
}

func (p *pastKey) toMap() map[string]interface{} {
	return map[string]interface{}{
		"key_layers": p.keyLayers,
		"signature":  p.sig,
		"algorithm":  p.algorithm,
	}
}

func (p *pastKey) SetSignature(signature string) bool {
	if signature == "" {
		return false
	}

	p.sig = signature
	return true
}

func (p *pastKey) SetSignatureByBytes(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	return p.SetSignature(string(data))
}

func (p *pastKey) SetSignatureByFunc(h func() hash.Hash) bool {
	if h == nil {
		return false
	}
	return p.SetSignatureByBytes(h().Sum(nil))
}

func (p *pastKey) GetSignatureRealLength() int {
	if p.sig == "" {
		return 0x0
	}
	myStr := C.CString(p.sig)
	defer C.free(unsafe.Pointer(myStr))
	return int(C.compute_signature_real_length(myStr, C.int(p.algorithm)))
}

func (p *pastKey) ToFutureKey() WotoKey {
	return nil
}

func (p *pastKey) ToPastKey() WotoKey {
	return p
}

func (p *pastKey) ToPresentKey() WotoKey {
	return nil
}

func (p *pastKey) Clone() WotoKey {
	return &pastKey{
		keyLayers: p.keyLayers,
		algorithm: p.algorithm,
		sig:       p.sig,
	}
}

func (p *pastKey) getLayers() KeyLayerCollection {
	return p.keyLayers
}

func (p *pastKey) setLayers(layers KeyLayerCollection) bool {
	p.keyLayers = layers
	return true
}

//---------------------------------------------------------
//---------------------------------------------------------
func (p privateBlock) IsValid() bool {
	return p != 0x0
}

func (p privateBlock) IsEmpty() bool {
	return p == 0x0 || p == 0x20
}

func (p privateBlock) IsNonZero() bool {
	return p != 0x0
}

func (p privateBlock) ToInt64() int64 {
	return int64(p)
}

func (p privateBlock) ToUInt64() uint64 {
	return uint64(p)
}
func (p privateBlock) ToInt32() int32 {
	return int32(p)
}

func (p privateBlock) ToUInt32() uint32 {
	return uint32(p)
}

func (p privateBlock) GetBitsSize() int {
	return strconv.IntSize
}

func (p privateBlock) Sum(other singleBlock) singleBlock {
	return privateBlock(p.ToInt64() + other.ToInt64())
}

func (p privateBlock) Min(other singleBlock) singleBlock {
	return privateBlock(p.ToInt64() - other.ToInt64())
}

func (p privateBlock) Mul(other singleBlock) singleBlock {
	if p.IsEmpty() || other.IsEmpty() {
		return p.Sum(other)
	}
	return privateBlock(p.ToInt64() * other.ToInt64())
}

func (p privateBlock) Div(other singleBlock) singleBlock {
	if p.IsEmpty() || other.IsEmpty() {
		return p.Min(other)
	}
	return privateBlock(p.ToInt64() / other.ToInt64())
}

//---------------------------------------------------------

func (c *privateCollection) GetBlocks() []singleBlock {
	var myBlocks []singleBlock
	for _, current := range c.blocks {
		myBlocks = append(myBlocks, current)
	}

	return myBlocks
}

func (c *privateCollection) GetRelativeIndex(index int) int {
	if index < c.Length() {
		return index
	}
	return index % c.Length()
}

func (c *privateCollection) Length() int {
	return len(c.blocks)
}

func (c *privateCollection) AppendBlock(b singleBlock) {
	c.blocks = append(c.blocks, privateBlock(b.ToInt64()))
}

func (c *privateCollection) AppendCollection(collection blockCollection) {
	if collection == nil || collection.Length() < 1 {
		return
	}

	allBlocks := collection.GetBlocks()
	for _, current := range allBlocks {
		c.AppendBlock(current)
	}
}

func (c *privateCollection) GetBlockByIndex(index int) singleBlock {
	return c.blocks[c.GetRelativeIndex(index)]
}

func (c *privateCollection) ToBytes() []byte {
	var rawData string
	for _, current := range c.blocks {
		rawData += string(current)
	}

	return []byte(rawData)
}

func (c *privateCollection) BlockSize() int {
	return c.Length()
}

func (c *privateCollection) Clone() blockCollection {
	return &privateCollection{
		blocks: c.clonePrivateBlocks(),
	}
}

func (c *privateCollection) clonePrivateBlocks() []privateBlock {
	var privateBlocks []privateBlock
	copy(privateBlocks, c.blocks)
	return privateBlocks
}

//---------------------------------------------------------

func (a *blockAlgorithmX917) GetEncryptBlockAction(index int) blockAction {
	if index%a.identifier == 0 {
		return blockActionSum
	}

	return blockActionMul
}
func (a *blockAlgorithmX917) GetDecryptBlockAction(index int) blockAction {
	if index%a.identifier == 0 {
		return blockActionMin
	}

	return blockActionDiv
}

//---------------------------------------------------------

func (a *blockAlgorithmX847) GetEncryptBlockAction(index int) blockAction {
	if index%a.identifier == 0 {
		return blockActionSum
	}

	return blockActionMul
}

func (a *blockAlgorithmX847) GetDecryptBlockAction(index int) blockAction {
	if index%a.identifier == 0 {
		return blockActionMin
	}

	return blockActionDiv
}

//---------------------------------------------------------

func (a *blockAlgorithmX795) GetEncryptBlockAction(index int) blockAction {
	if index%a.identifier == 0 {
		return blockActionSum
	}

	return blockActionMul
}

func (a *blockAlgorithmX795) GetDecryptBlockAction(index int) blockAction {
	if index%a.identifier == 0 {
		return blockActionMin
	}

	return blockActionDiv
}

//---------------------------------------------------------

func (a *blockAlgorithmX649) GetEncryptBlockAction(index int) blockAction {
	if index%a.identifier == 0 {
		return blockActionSum
	}

	return blockActionMul
}

func (a *blockAlgorithmX649) GetDecryptBlockAction(index int) blockAction {
	if index%a.identifier == 0 {
		return blockActionMin
	}

	return blockActionDiv
}

//---------------------------------------------------------
//---------------------------------------------------------
//---------------------------------------------------------
//---------------------------------------------------------
