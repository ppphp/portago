package emerge

import (
	"fmt"
	"github.com/ppphp/portago/pkg/output"
	"golang.org/x/sys/unix"
	"strings"
	"syscall"
)

type UserQuery struct {
	myopts map[string]string
}

// nil, nil
func (u *UserQuery) query(prompt string, enterInvalid bool, responses []string, colours []func(string) string) string {
	if responses == nil {
		responses = []string{"Yes", "No"}
		colours = []func(string) string{
			output.NewCreateColorFunc("PROMPT_CHOICE_DEFAULT"),
			output.NewCreateColorFunc("PROMPT_CHOICE_OTHER"),
		}
	} else if colours == nil {
		colours = []func(string) string{output.Bold}
	}
	cs := []func(string) string{}
	for i := range responses {
		cs = append(cs, colours[i%len(colours)])
	}
	colours = cs
	if _, ok := u.myopts["--alert"]; ok {
		prompt = "\a" + prompt
	}
	print(output.Bold(prompt) + " ")
	for {
		rs := []string{}
		for i := range responses {
			rs = append(rs, colours[i](responses[i]))
		}
		ipt := fmt.Sprintf("[%s] ", strings.Join(rs, "/"))

		fmt.Print(ipt)
		response := ""
		_, err := fmt.Scanln(&response)
		if err != nil {
			//except (EOFError, KeyboardInterrupt):
			print("Interrupted.")
			syscall.Exit(128 + int(unix.SIGINT))
		}
		if len(response) > 0 || !enterInvalid {
			for _, key := range responses {
				if strings.ToUpper(response) == strings.ToUpper(key[:len(response)]) {
					return key
				}
			}
		}
		print(fmt.Sprintf("Sorry, response '%s' not understood.", response) + " ")
	}
	//except (EOFError, KeyboardInterrupt):
	//	print("Interrupted.")
	//	sys.exit(128 + signal.SIGINT)
	return ""
}

func NewUserQuery(myopts map[string]string) *UserQuery {
	u := &UserQuery{myopts: myopts}
	return u
}
