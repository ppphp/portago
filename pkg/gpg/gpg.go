package gpg

import (
	"fmt"
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/shlex"
	"github.com/tudurom/ttyname"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"
)

type GPG struct {
	settings                                                                                     *config.Config
	GPG_signing_base_command, digest_algo, signing_gpg_home, signing_gpg_key, GPG_unlock_command string
	keepalive                                                                                    bool
	thread                                                                                       *int
}

func NewGPG(settings *config.Config) *GPG {
	g := &GPG{}
	g.settings = settings
	g.thread = nil
	g.GPG_signing_base_command = g.settings.ValueDict["BINPKG_GPG_SIGNING_BASE_COMMAND"]
	g.digest_algo = g.settings.ValueDict["BINPKG_GPG_SIGNING_DIGEST"]
	g.signing_gpg_home = g.settings.ValueDict["BINPKG_GPG_SIGNING_GPG_HOME"]
	g.signing_gpg_key = g.settings.ValueDict["BINPKG_GPG_SIGNING_KEY"]
	g.GPG_unlock_command = strings.ReplaceAll(g.GPG_signing_base_command,
		"[PORTAGE_CONFIG]",
		fmt.Sprintf("--homedir %s --digest-algo %s --local-user %s --output /dev/null /dev/null",
			g.signing_gpg_home, g.digest_algo, g.signing_gpg_key))

	if g.settings.Features.Features["gpg-keepalive"] {
		g.keepalive = true
	} else {
		g.keepalive = false
	}
	return g
}

func (g *GPG) unlock() {
	if g.GPG_unlock_command != "" && g.settings.ValueDict["BINPKG_FORMAT"] == "gpkg" {

		tty, err := ttyname.TTY()
		if err != nil {
			err = os.Setenv("GPG_TTY", tty)
		}
		if err != nil {
			//except OSError as e:
			msg.WriteMsg(output.Colorize("WARN", err.Error())+"\n", 0, nil)
		}
	}

	nr := strings.NewReader(util.VarExpand(g.GPG_unlock_command, g.settings.ValueDict, nil))
	cmd, _ := shlex.Split(nr, false, true)
	return_code := exec.Command(cmd[0], cmd[1:]...).Run()

	if return_code == nil {
		msg.WriteMsgStdout(output.Colorize("GOOD", "unlocked")+"\n", 0)
		os.Stdout.Sync()
	} else {
		//raise GPGException("GPG unlock failed")
	}

	if g.keepalive {

		nr := strings.NewReader(util.VarExpand(g.GPG_unlock_command, g.settings.ValueDict, nil))
		//g.GPG_unlock_command, _ = shlex.Split(nr, false,true)
		gnc, _ := ioutil.ReadAll(nr)
		g.GPG_unlock_command = string(gnc)

		go g.gpg_keepalive()
		a := 1
		g.thread = &a
	}
}

func (g *GPG) stop() {
	if g.thread != nil {
		g.keepalive = false
	}
}

func (g *GPG) gpg_keepalive() {
	count := 0
	for g.keepalive {
		if count < 5 {
			time.Sleep(60 * time.Second)
			count += 1
			continue
		} else {
			count = 0
		}

		cmd := exec.Command(g.GPG_unlock_command)
		cmd.Stderr = os.Stdout
		cmd.Run()
		if cmd.Wait() != nil {
			//raise GPGException("GPG keepalive failed")
		}
	}
}
