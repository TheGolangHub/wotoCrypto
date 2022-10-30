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
