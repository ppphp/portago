package atom

import "testing"

func TestVerCmpGreater(t *testing.T) {
	for _, test := range [][2]string{
		{"6.0", "5.0"},
		{"5.12", "5.2"},
		{"5.0", "5"},
		{"1.0-r1", "1.0-r0"},
		{"1.0-r1", "1.0"},
		{"999999999999999999999999999999", "999999999999999999999999999998"},
		{"1.0.0", "1.0"},
		{"1.0.0", "1.0b"},
		{"1b", "1"},
		{"1b_p1", "1_p1"},
		{"1.1b", "1.1"},
		{"12.2.5", "12.2b"}} {
		if ans, err := verCmp(test[0], test[1]); err != nil {
			t.Fatalf("vercmp error (%v)\n", err)
		} else if ans <= 0 {
			t.Errorf("vercmp wrong, %v < %v? Wrong!\n", test[0], test[1])
		}
	}
}

func TestVerCmpLess(t *testing.T) {
	for _, test := range [][2]string{
		{"4.0", "5.0"}, {"5", "5.0"}, {"1.0_pre2", "1.0_p2"},
		{"1.0_alpha2", "1.0_p2"}, {"1.0_alpha1", "1.0_beta1"}, {"1.0_beta3", "1.0_rc3"},
		{"1.001000000000000000001", "1.001000000000000000002"},
		{"1.00100000000", "1.0010000000000000001"},
		{"999999999999999999999999999998", "999999999999999999999999999999"},
		{"1.01", "1.1"},
		{"1.0-r0", "1.0-r1"},
		{"1.0", "1.0-r1"},
		{"1.0", "1.0.0"},
		{"1.0b", "1.0.0"},
		{"1_p1", "1b_p1"},
		{"1", "1b"},
		{"1.1", "1.1b"},
		{"12.2b", "12.2.5"}} {
		if ans, err := verCmp(test[0], test[1]); err != nil {
			t.Fatalf("vercmp error (%v)\n", err)
		} else if ans >= 0 {
			t.Errorf("vercmp wrong, %v >= %v\n", test[0], test[1])
		}
	}
}

func TestVerCmpEqual(t *testing.T) {
	for _, test := range [][2]string{
		{"4.0", "4.0"},
		{"1.0", "1.0"},
		{"1.0-r0", "1.0"},
		{"1.0", "1.0-r0"},
		{"1.0-r0", "1.0-r0"},
		{"1.0-r1", "1.0-r1"}} {
		if ans, err := verCmp(test[0], test[1]); err != nil {
			t.Fatalf("vercmp error (%v)\n", err)
		} else if ans != 0 {
			t.Errorf("vercmp wrong, %v != %v\n", test[0], test[1])
		}
	}
}

func TestVerNotEqual(t *testing.T) {
	for _, test := range [][2]string{
		{"1", "2"}, {"1.0_alpha", "1.0_pre"}, {"1.0_beta", "1.0_alpha"},
		{"0", "0.0"},
		{"1.0-r0", "1.0-r1"},
		{"1.0-r1", "1.0-r0"},
		{"1.0", "1.0-r1"},
		{"1.0-r1", "1.0"},
		{"1.0", "1.0.0"},
		{"1_p1", "1b_p1"},
		{"1b", "1"},
		{"1.1b", "1.1"},
		{"12.2b", "12.2"}} {
		if ans, err := verCmp(test[0], test[1]); err != nil {
			t.Fatalf("vercmp error (%v)\n", err)
		} else if ans == 0 {
			t.Errorf("vercmp wrong, %v == %v\n", test[0], test[1])
		}
	}
}

func TestCpvSortKey(t *testing.T) {


	for _, test := range 
		tests = [
			(("a/b-2_alpha", "a", "b", "a/b-2", "a/a-1", "a/b-1"),
			 ("a", "a/a-1", "a/b-1", "a/b-2_alpha", "a/b-2", "b")),
		]

		for test in tests:
			self.assertEqual(tuple(sorted(test[0], key=cpv_sort_key())), test[1])
}
