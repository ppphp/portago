package exception

type PortageException struct {
	s string
	t string
}

func (p *PortageException) Error() string {
	return p.s
}

func Raise(s, msg string) PortageException {
	return PortageException{t: s, s: msg}
}

func ExceptionMatch(a, b PortageException) bool {
	return a.t == b.t
}
