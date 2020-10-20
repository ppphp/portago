package atom

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

type OptionItem struct {
	short, long, target, help, status, fun, action, typ, dest, choices string
}

func (o *OptionItem) pargs() []string {
	pargs := []string{}
	if o.short != "" {
		pargs = append(pargs, o.short)
	}
	if o.long != "" {
		pargs = append(pargs, o.long)
	}
	return pargs
}

func (o *OptionItem) kwargs() map[string]string {
	kwargs := map[string]string{}
	if o.help != "" {
		kwargs["help"] = o.help
	}
	if o.action != "" {
		kwargs["action"] = o.action
	}
	if o.typ != "" {
		kwargs["type"] = o.typ
	}
	if o.dest != "" {
		kwargs["dest"] = o.dest
	}
	if o.choices != "" {
		kwargs["choices"] = o.choices
	}
	return kwargs
}

func NewOptionItem(opt map[string]string) *OptionItem {
	o := &OptionItem{}

	o.short = opt["short"]
	o.long = opt["long"]
	o.target = strings.ReplaceAll(o.long[2:], "-", "_")
	o.help = opt["help"]
	o.status = opt["status"]
	o.fun = opt["func"]
	o.action = opt["action"]
	o.typ = opt["type"]
	o.dest = opt["dest"]
	o.choices = opt["choices"]

	return o
}

func usage(module_controller) string {
	_usage := "usage: emaint [options] COMMAND"

	desc := "The emaint program provides an interface to system health " +
		"checks and maintenance. See the emaint(1) man page " +
		"for additional information about the following commands:"

	_usage += "\n\n"
	for _, line := range SplitSubN(desc, 65) {
		_usage += fmt.Sprintf("%s\n", line)
		_usage += "\nCommands:\n"
		_usage += fmt.Sprintf("  %s", fmt.Sprintf("%15s", "all")) +
			"Perform all supported commands\n"
		subsequent_indent := fmt.Sprintf("%17s", " ")
		for _, mod := range module_controller.module_names {
			desc := SplitSubN(module_controller.get_description(mod), 65)
			_usage += fmt.Sprintf("  %s%s\n", fmt.Sprintf("%15s", mod), desc[0])
			for _, d := range desc[1:] {
				_usage += subsequent_indent + fmt.Sprintf("  %s%s\n", fmt.Sprintf("%15s", " "), d)
			}
		}
	}
	return _usage
}

func module_opts(module_controller, module) string {
	_usage := fmt.Sprintf(" %s module options:\n", module)
	opts := module_controller.get_func_descriptions(module)
	if len(opts) == 0 {
		opts = DEFAULT_OPTIONS
	}

	for opt := range opts {
		optd := opts[opt]
		opto := ""
		if _, ok := optd["short"]; ok {
			opto = fmt.Sprintf("  %s, %s", optd["short"], optd["long"])
		} else {
			opto = fmt.Sprintf("  %s", optd["long"])
		}
		_usage += fmt.Sprintf("%s %s\n", fmt.Sprintf("%15s", opto), optd["help"])
	}

	_usage += "\n"
	return _usage
}

type TaskHandler struct {
	show_progress_bar, verbose, isatty bool
	callback                           func()
	module_output                      interface{}
	progress_bar                       *ProgressBar2
}

func NewTaskHandler(show_progress_bar, verbose bool, callback func(), module_output interface{}) *TaskHandler { // true, true, nil, nil
	t := &TaskHandler{}
	t.show_progress_bar = show_progress_bar
	t.verbose = verbose
	t.callback = callback
	t.module_output = module_output
	_, err := unix.IoctlGetTermios(int(os.Stdout.Fd()), unix.TCGETS)
	t.isatty = os.Getenv("TERM") != "dumb" && err == nil
	t.progress_bar = NewProgressBar2(t.isatty, os.Stdout, "Emaint", 0, "", 27)
	return t
}

func (t *TaskHandler) run_tasks(tasks []task, fun, status, verbose bool, options string) []int { // nil, true, nil
	if tasks == nil || fun == nil {
		return nil
	}
	returncodes := []int{}
	for _, task := range tasks {
		inst := task()
		show_progress := t.show_progress_bar && t.isatty
		if show_progress && hasattr(inst, "can_progressbar") {
			show_progress = inst.can_progressbar(fun)
		}
		var onProgress func(int64, int64)
		if show_progress {
			t.progress_bar.Reset()
			t.progress_bar.SetLabel(fun + " " + inst.name())
			onProgress = t.progress_bar.Start()
		} else {
			onProgress = nil
		}
		kwargs = map[string]interface{}{
			"onProgress":    onProgress,
			"module_output": t.module_output,
			"options":       options.copy(),
		}
		returncode, msgs := getattr(inst, fun)(**kwargs)
		returncodes = append(retruncodes, returncode)
		if show_progress {
			t.progress_bar.Display()
			print()
			t.progress_bar.Stop()
		}
		if t.callback != nil {
			t.callback(msgs)
		}
	}
	return returncodes
}

func print_results(results []string) {
	if len(results) > 0 {
		println()
		println(strings.Join(results, "\n"))
		println("\n")
	}
}
