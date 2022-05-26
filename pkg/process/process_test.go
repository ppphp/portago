package process

import (
	cons "github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/util/msg"
	"runtime"
	"testing"
)

const CLONE_NEWNET = 0x40000000

const UNSHARE_NET_TEST_SCRIPT = `
ping -c 1 -W 1 127.0.0.1 || exit 1
ping -c 1 -W 1 10.0.0.1 || exit 1
[[ -n ${IPV6} ]] || exit 0
ping -c 1 -W 1 ::1 || exit 1
ping -c 1 -W 1 fd::1 || exit 1
`

func TestUnsharedNet(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("not Linux")
	}

	if FindBinary("ping") == "" {
		t.Skip("ping not found")
	}

	errno_value := _unshare_validate.call(CLONE_NEWNET)
	if errno_value != 0 {
		t.Skipf("Unable to unshare: %d", errno_value) //errno.errorcode.get(errno_value, "?"))
	}

	//env := os.Environ()
	//os["IPV6"] = "1" if portage.process._has_ipv6() else ""
	env := msg.ExpandEnv()
	env["IPV6"] = "1"

	ret, err := Spawn([]string{cons.BashBinary, "-c", UNSHARE_NET_TEST_SCRIPT}, env, "", nil, false, 0, 0, nil, 0, "", "", true, nil, false, true, false, false, false, "")
	if err != nil {
		t.Error()
	}
	if len(ret) != 1 || ret[0] != 0 {
		t.Error()
	}

}
