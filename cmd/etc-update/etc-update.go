package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func getConfig() {
	match := ""
	if len(os.Args) >= 2 {
		match = os.Args[1]
	}
}

const (
	_3_HELP_TEXT = "-3 to auto merge all files"
	_5_HELP_TEXT = "-5 to auto-merge AND not use 'mv -i'"
	_7_HELP_TEXT = "-7 to discard all updates"
	_9_HELP_TEXT = "-9 to discard all updates AND not use 'rm -i'"
)

func usage(code int) {
	fmt.Printf(`etc-update: Handle configuration file updates

Usage: etc-update [options] [paths to scan]

If no paths are specified, then ${CONFIG_PROTECT} will be used.

Options:
  -d, --debug    Enable shell debugging
  -h, --help     Show help and run away
  -p, --preen    Automerge trivial changes only and quit
  -q, --quiet    Show only essential output
  -v, --verbose  Show settings and such along the way
  -V, --version  Show version and trundle away

  --automode <mode>
             %v
             %v
             %v
             %v
EOF
`, _3_HELP_TEXT, _5_HELP_TEXT, _7_HELP_TEXT, _9_HELP_TEXT)
	os.Exit(code)

}

func cmd_var_is_valid()          {}
func diff_command()              {}
func do_mv_ln()                  {}
func scan()                      {}
func parse_automode_flag(string) {}
func sel_file()                  {}
func user_special()              {}
func read_int()                  {}
func do_file()                   {}
func show_diff()                 {}
func do_cfg()                    {}
func do_merge()                  {}

func error(errMsg string) int {
	os.Stderr.Write([]byte("etc-update: ERROR: " + errMsg + "\n"))
	return 1
}

func die(msg string, exitcode *int) {
	if exitcode == nil {
		exitcode = new(int)
		*exitcode = -1
	}
	if *exitcode == 0 {
	} else {
		error(msg)
	}
	os.Exit(*exitcode)
}

func main() {
	os.Chdir("/")
	cmd := exec.Command("source", "/etc/os-release")
	cmd.Run()
	osReleasePossibleIds := ":" + os.Getenv("ID") + ":" + os.Getenv("ID_LIKE") + "//[[:space:]]/:}:"
	osFamily := "gentoo"
	if strings.Contains(osReleasePossibleIds, ":suse:") || strings.Contains(osReleasePossibleIds, ":opensuse:") || strings.Contains(osReleasePossibleIds, ":opensuse-tumbleweed:") {
		osFamily = "rpm"
	} else if strings.Contains(osReleasePossibleIds, ":fedora:") || strings.Contains(osReleasePossibleIds, ":rhel:") {
		osFamily = "rpm"
	} else if strings.Contains(osReleasePossibleIds, ":arch:") {
		osFamily = "pacnew"
	}

	var get_basename, getBasenameFindOpt func(string) string
	if osFamily == "gentoo" {
		get_basename = func(b string) string {
			return b + "\n"
		}
		getBasenameFindOpt = func(b string) string {
			return fmt.Sprintf("._cfg???_%v", b)
		}
		getScanRegexp = func() {}
	}

	count := 0
	input := 0
	title := "Gentoo's etc-update tool!"

	PREEN := false
	SET_X := false
	QUIET := false
	VERBOSE := false
	NONINTERACTIVE_MV := false

	args := os.Args[1:]
	for i := range args {
		switch args[i] {
		case "-d", "--debug":
			SET_X = true
		case "-h", "--help":
			usage(0)
		case "-p", "--preen":
			PREEN = true
		case "-q", "--quiet":
			QUIET = true
		case "-v", "--verbose":
			VERBOSE = true
		case "-V", "--version":
			cmd := exec.Command("emerge", "--version")
			cmd.Stdout = os.Stdout
			cmd.Run()
			os.Exit(0)
		case "--automode":
			if i+1 < len(args) {
				parse_automode_flag(args[i+1])
				i++
			} else {
			}
		default:
			usage(1)
		}
	}
	if SET_X {
		// set -x
	}

	portage_vars := []string{
		"CONFIG_PROTECT{,_MASK}",
		"FEATURES",
		"PORTAGE_CONFIGROOT",
		"PORTAGE_INST_{G,U}ID",
		"PORTAGE_TMPDIR",
		"EROOT",
		"USERLAND",
		"NOCOLOR",
	}
	if exec.Command("type", "-P", "portageq").Run() == nil {
		ans := &bytes.Buffer{}
		cmd := exec.Command("portageq", append([]string{"envvar", "-v"}, portage_vars...)...)
		cmd.Stdout = ans
		cmd.Run()
		for _, line := range strings.Split(ans.String(), "\n") {
			kv := strings.SplitN(line, "=", 2)
			if len(kv) == 2 {
				os.Setenv(kv[0], kv[1])
			}
		}

	} else {
		if osFamily == "gentoo" {
			die("missing portageq", nil)
		}
	}

	os.Exit(0)
}
