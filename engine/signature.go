package engine

func (s *Signature1) Encode() []byte {
	return append(s.R, s.S...)
}

func (s *Signature2) Encode() []byte {
	return append(s.R, s.S...)
}
