package ebuild

import "strconv"

type ExitCommand struct {
	IpcCommand
	Reply_hook
	Exitcode *int
}

func NewExitCommand() *ExitCommand {
	return &ExitCommand{}
}

func (e *ExitCommand) Call(argv []string) (string, string, int) {
	if e.Exitcode != nil {
		e.Reply_hook = nil

	} else {
		*e.Exitcode, _ = strconv.Atoi(argv[1])
	}
	return "", "", 0
}
