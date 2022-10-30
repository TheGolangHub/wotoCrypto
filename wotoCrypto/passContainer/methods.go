package passContainer

import "hash"

//---------------------------------------------------------

// HasSignature returns true if and only if this password container has a valid
// signature field.
func (c *PasswordContainer256) HasSignature() bool {
	return len(c.Signature) > 0x010 && len(c.Signature)%2 != 1
}

// GetSignature returns the signature field of this password container.
func (c *PasswordContainer256) GetSignature() string {
	return c.Signature
}

// SetSignature will try to set the given value as the signature of this
// password container.
// Returns `true` if and only if the value can be set as signature.
func (c *PasswordContainer256) SetSignature(signature string) bool {
	if len(signature) > 0x010 && len(signature)%2 != 1 {
		c.Signature = signature
		return true
	}
	return false
}

// SetSignatureByBytes will try to set the given value as the signature of this
// password container.
// Returns `true` if and only if the value can be set as signature.
func (c *PasswordContainer256) SetSignatureByBytes(data []byte) bool {
	return c.SetSignature(string(data))
}

// SetSignatureByFunc will try to call the given function and use the hash
// value returned by it to set it as the signature of this password container.
// Returns `true` if and only if the value can be set as signature.
func (c *PasswordContainer256) SetSignatureByFunc(h func() hash.Hash) bool {
	if h == nil {
		return false
	}
	return c.SetSignatureByBytes(h().Sum(nil))
}

//---------------------------------------------------------

// HasSignature returns true if and only if this password container has a valid
// signature field.
func (c *PasswordContainer512) HasSignature() bool {
	return len(c.Signature) > 0x020 && len(c.Signature)%2 != 1
}

// GetSignature returns the signature field of this password container.
func (c *PasswordContainer512) GetSignature() string {
	return c.Signature
}

// SetSignature will try to set the given value as the signature of this
// password container.
// Returns `true` if and only if the value can be set as signature.
func (c *PasswordContainer512) SetSignature(signature string) bool {
	if len(signature) > 0x020 && len(signature)%2 != 1 {
		c.Signature = signature
		return true
	}
	return false
}

// SetSignatureByBytes will try to set the given value as the signature of this
// password container.
// Returns `true` if and only if the value can be set as signature.
func (c *PasswordContainer512) SetSignatureByBytes(data []byte) bool {
	return c.SetSignature(string(data))
}

// SetSignatureByFunc will try to call the given function and use the hash
// value returned by it to set it as the signature of this password container.
// Returns `true` if and only if the value can be set as signature.
func (c *PasswordContainer512) SetSignatureByFunc(h func() hash.Hash) bool {
	if h == nil {
		return false
	}
	return c.SetSignatureByBytes(h().Sum(nil))
}

//---------------------------------------------------------
