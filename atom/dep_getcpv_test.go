package atom

import "testing"

func TestDepGetCPV(t *testing.T) {

	prefix_ops := []string{
		"<", ">", "=", "~", "<=",
		">=", "!=", "!<", "!>", "!~",
	}

	//bad_prefix_ops := []string{">~", "<~", "~>", "~<"}
	//	postfix_ops = [("=", "*"),]

	cpvs := []string{"sys-apps/portage-2.1", "sys-apps/portage-2.1",
		"sys-apps/portage-2.1"}
	slots := []string{"", ":foo", ":2"}
	for _, cpv := range cpvs {
		for _, slot := range slots {
			for _, prefix := range prefix_ops {
				mycpv := prefix + cpv
				if len(slot) > 0 {
					mycpv += slot
				}
				if depGetcpv(mycpv).string != cpv {
					t.Errorf("%v != %v", depGetcpv(mycpv), cpv)
				}
			}

			prefix, postfix := "=", "*"
			mycpv := prefix + cpv + postfix
			if len(slot) > 0 {
				mycpv += slot
			}
			if depGetcpv(mycpv).string != cpv {
				t.Errorf("%v != %v", depGetcpv(mycpv), cpv)
			}
		}
	}
}
