package main

import (
	"fmt"
	"github.com/ppphp/portago/atom"
	"github.com/ppphp/portago/pkg/xpak"
	"github.com/spf13/pflag"
	"os"
)

func init() {
	atom.InternalCaller = true
}
func command_recompose(args []string) int {

	usage := "usage: recompose <binpkg_path> <metadata_dir>\n"

	if len(args) != 2 {
		os.Stderr.Write([]byte(usage))
		os.Stderr.Write([]byte(fmt.Sprintf("2 arguments are required, got %s\n", len(args))))
		return 1
	}
	binpkg_path, metadata_dir := args[0], args[1]

	if st, err := os.Stat(binpkg_path); err != nil || st.IsDir() {
		os.Stderr.Write([]byte(usage))
		os.Stderr.Write([]byte(fmt.Sprintf("Argument 1 is not a regular file: '%s'\n", binpkg_path)))
		return 1
	}

	if st, err := os.Stat(metadata_dir); err != nil || !st.IsDir() {
		os.Stderr.Write([]byte(usage))
		os.Stderr.Write([]byte(fmt.Sprintf("Argument 2 is not a directory: '%s'\n", metadata_dir)))
		return 1
	}

	t := xpak.NewTbz2(binpkg_path)
	t.Recompose(metadata_dir, 0, true)
	return 0
}

func main() {

	valid_commands := map[string]bool{"recompose": true}
	//description := "Perform metadata operations on a binary package."
	//usage := "usage: %s COMMAND [args]" % os.path.basename(argv[0])

	pflag.Parse()

	args := pflag.Args()

	//parser = argparse.ArgumentParser(description=description, usage=usage)
	//options, args = parser.parse_known_args(argv[1:])

	if len(args) == 0 {
		// parser.error("missing command argument")
	}

	command := args[0]

	if !valid_commands[command] {
		// parser.error("invalid command: '%s'" % command)
	}

	var rval int
	if command == "recompose" {
		rval = command_recompose(args[1:])
	} else {
		//raise AssertionError("invalid command: '%s'" % command)
	}
	os.Exit(rval)
}
