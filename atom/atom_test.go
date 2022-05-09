package atom

import (
	"github.com/ppphp/portago/pkg/versions"
	"testing"
)

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
		if ans, err := versions.verCmp(test[0], test[1]); err != nil {
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
		//		{"1.01", "1.1"},
		{"1.0-r0", "1.0-r1"},
		{"1.0", "1.0-r1"},
		{"1.0", "1.0.0"},
		{"1.0b", "1.0.0"},
		{"1_p1", "1b_p1"},
		{"1", "1b"},
		{"1.1", "1.1b"},
		{"12.2b", "12.2.5"}} {
		if ans, err := versions.verCmp(test[0], test[1]); err != nil {
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
		if ans, err := versions.verCmp(test[0], test[1]); err != nil {
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
		if ans, err := versions.verCmp(test[0], test[1]); err != nil {
			t.Fatalf("vercmp error (%v)\n", err)
		} else if ans == 0 {
			t.Errorf("vercmp wrong, %v == %v\n", test[0], test[1])
		}
	}
}

func TestAtom(t *testing.T) {
	/*
		tests := []string{

				("=sys-apps/portage-2.1-r1:0[doc,a=,!b=,c?,!d?,-e]",
					('=',  'sys-apps/portage', '2.1-r1', '0', '[doc,a=,!b=,c?,!d?,-e]', None), False, False),
				("=sys-apps/portage-2.1-r1*:0[doc]",
					('=*',  'sys-apps/portage', '2.1-r1', '0', '[doc]', None), False, False),
				("sys-apps/portage:0[doc]",
					(None,  'sys-apps/portage', None, '0', '[doc]', None), False, False),
				("sys-apps/portage:0[doc]",
					(None,  'sys-apps/portage', None, '0', '[doc]', None), False, False),*/
	//			("*/*",
	//				(None,  '*/*', None, None, None, None), True, False),
	//		("=*/*-*9999*",
	//			('=*',  '*/*', '*9999*', None, None, None), True, False),
	//		("=*/*-*9999*:0::repo_name",
	//			('=*',  '*/*', '*9999*', '0', None, 'repo_name'), True, True),
	//		("=*/*-*_beta*",
	//			('=*',  '*/*', '*_beta*', None, None, None), True, False),
	//		("=*/*-*_beta*:0::repo_name",
	//			('=*',  '*/*', '*_beta*', '0', None, 'repo_name'), True, True),
	//		("sys-apps/*",
	//			(None,  'sys-apps/*', None, None, None, None), True, False),
	//		("*/portage",
	//			(None,  '*/portage', None, None, None, None), True, False),
	//		("s*s-*/portage:1",
	//			(None,  's*s-*/portage', None, '1', None, None), True, False),
	//		("*/po*ge:2",
	//			(None,  '*/po*ge', None, '2', None, None), True, False),
	/*		("!dev-libs/A",
				(None,  'dev-libs/A', None, None, None, None), True, True),
			("!!dev-libs/A",
				(None,  'dev-libs/A', None, None, None, None), True, True),
			("!!dev-libs/A",
				(None,  'dev-libs/A', None, None, None, None), True, True),
			("dev-libs/A[foo(+)]",
				(None,  'dev-libs/A', None, None, "[foo(+)]", None), True, True),
			("dev-libs/A[a(+),b(-)=,!c(+)=,d(-)?,!e(+)?,-f(-)]",
				(None,  'dev-libs/A', None, None, "[a(+),b(-)=,!c(+)=,d(-)?,!e(+)?,-f(-)]", None), True, True),
			("dev-libs/A:2[a(+),b(-)=,!c(+)=,d(-)?,!e(+)?,-f(-)]",
				(None,  'dev-libs/A', None, "2", "[a(+),b(-)=,!c(+)=,d(-)?,!e(+)?,-f(-)]", None), True, True),

			("=sys-apps/portage-2.1-r1:0::repo_name[doc,a=,!b=,c?,!d?,-e]",
				('=',  'sys-apps/portage', '2.1-r1', '0', '[doc,a=,!b=,c?,!d?,-e]', 'repo_name'), False, True),
			("=sys-apps/portage-2.1-r1*:0::repo_name[doc]",
				('=*',  'sys-apps/portage', '2.1-r1', '0', '[doc]', 'repo_name'), False, True),
			("sys-apps/portage:0::repo_name[doc]",
				(None,  'sys-apps/portage', None, '0', '[doc]', 'repo_name'), False, True),*/
	//
	//		("*/*::repo_name",
	//			(None,  '*/*', None, None, None, 'repo_name'), True, True),
	//		("sys-apps/*::repo_name",
	//			(None,  'sys-apps/*', None, None, None, 'repo_name'), True, True),
	//		("*/portage::repo_name",
	//			(None,  '*/portage', None, None, None, 'repo_name'), True, True),
	//		("s*s-*/portage:1::repo_name",
	//			(None,  's*s-*/portage', None, '1', None, 'repo_name'), True, True),

	{
		a, err := NewAtom("=sys-apps/portage-2.1-r1:0[doc,a=,!b=,c?,!d?,-e]", nil, false, nil, nil, "", nil, nil)
		if err != nil {
			t.Errorf("%v\n", err)
		}
		if a.Operator != "=" || a.cp != "sys-apps/portage" || a.version != "2.1-r1" || a.slot != "0" || a.Use.str() != "[doc,a=,!b=,c?,!d?,-e]" || a.repo != "" {
			t.Errorf("not match %v %v %v %v %v %v", a.Operator, a.cp, a.version, a.slot, a.Use.str(), a.repo)
		}
	}
	/*
		tests_xfail = (
			(Atom("sys-apps/portage"), False, False),
			("cat/pkg[a!]", False, False),
			("cat/pkg[!a]", False, False),
			("cat/pkg[!a!]", False, False),
			("cat/pkg[!a-]", False, False),
			("cat/pkg[-a=]", False, False),
			("cat/pkg[-a?]", False, False),
			("cat/pkg[-a!]", False, False),
			("cat/pkg[=a]", False, False),
			("cat/pkg[=a=]", False, False),
			("cat/pkg[=a?]", False, False),
			("cat/pkg[=a!]", False, False),
			("cat/pkg[=a-]", False, False),
			("cat/pkg[?a]", False, False),
			("cat/pkg[?a=]", False, False),
			("cat/pkg[?a?]", False, False),
			("cat/pkg[?a!]", False, False),
			("cat/pkg[?a-]", False, False),
			("sys-apps/portage[doc]:0", False, False),*/
	//			("*/*", False, False),
	//		("sys-apps/*", False, False),
	//		("*/portage", False, False),
	//		("*/**", True, False),
	//		("*/portage[Use]", True, False),
	/*("cat/pkg[a()]", False, False),
	("cat/pkg[a(]", False, False),
	("cat/pkg[a)]", False, False),
	("cat/pkg[a(,b]", False, False),
	("cat/pkg[a),b]", False, False),
	("cat/pkg[a(*)]", False, False),
	("cat/pkg[a(*)]", True, False),
	("cat/pkg[a(+-)]", False, False),
	("cat/pkg[a()]", False, False),
	("cat/pkg[(+)a]", False, False),
	("cat/pkg[a=(+)]", False, False),
	("cat/pkg[!(+)a=]", False, False),
	("cat/pkg[!a=(+)]", False, False),
	("cat/pkg[a?(+)]", False, False),
	("cat/pkg[!a?(+)]", False, False),
	("cat/pkg[!(+)a?]", False, False),
	("cat/pkg[-(+)a]", False, False),
	("cat/pkg[a(+),-a]", False, False),
	("cat/pkg[a(-),-a]", False, False),
	("cat/pkg[-a,a(+)]", False, False),
	("cat/pkg[-a,a(-)]", False, False),
	("cat/pkg[-a(+),a(-)]", False, False),
	("cat/pkg[-a(-),a(+)]", False, False),
	("sys-apps/portage[doc]::repo_name", False, False),
	("sys-apps/portage:0[doc]::repo_name", False, False),
	("sys-apps/portage[doc]:0::repo_name", False, False),
	("=sys-apps/portage-2.1-r1:0::repo_name[doc,a=,!b=,c?,!d?,-e]", False, False),
	("=sys-apps/portage-2.1-r1*:0::repo_name[doc]", False, False),
	("sys-apps/portage:0::repo_name[doc]", False, False),*/
	//			("*/*::repo_name", True, False),
	//)

}
