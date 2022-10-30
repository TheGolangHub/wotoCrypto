// wotoCrypto Project
// Copyright (C) 2022 ALiwoto
// This file is subject to the terms and conditions defined in
// file 'LICENSE', which is part of the source code.

package passContainer

type PasswordContainer256 struct {
	Header    string `json:"header"`
	Hash256   string `json:"hash256"`
	Signature string `json:"signature"`
}

type PasswordContainer512 struct {
	Header    string `json:"header"`
	Hash512   string `json:"hash512"`
	Hash256   string `json:"hash256"`
	Signature string `json:"signature"`
}
