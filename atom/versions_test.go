package atom

import "testing"

func TestVerCmpGreater(t *testing.T) {
	for _, c := range [][2]string{
		{"6.0", "5.0"},
		{"5.0", "5"},
		{"1.0-r1", "1.0-r0"},
		{"1.0-r1", "1.0"},
		{"999999999999999999999999999999", "999999999999999999999999999998"},
		{"1.0.0", "1.0"},
		{"1.0.0", "1.0b"},
		{"1b", "1"},
		{"1b_p1", "1_p1"},
		{"1.1b", "1.1"},
		{"12.2.5", "12.2b"},}{
			i, err := verCmp(c[0], c[1])
			if err!= nil && i <= 0{
				t.Errorf("%v <= %v, or wrong(%v)", c[0], c[1], err)
			}
	}
}
