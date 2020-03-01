package atom

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

var (
	HaveColor = 1
	doTitles  = 1
	styles    = map[string][]string{
		"NORMAL":                  {"normal"},
		"GOOD":                    {"green"},
		"WARN":                    {"yellow"},
		"BAD":                     {"red"},
		"HILITE":                  {"teal"},
		"BRACKET":                 {"blue"},
		"INFORM":                  {"darkgreen"},
		"UNMERGE_WARN":            {"red"},
		"SECURITY_WARN":           {"red"},
		"MERGE_LIST_PROGRESS":     {"yellow"},
		"PKG_BLOCKER":             {"red"},
		"PKG_BLOCKER_SATISFIED":   {"darkblue"},
		"PKG_MERGE":               {"darkgreen"},
		"PKG_MERGE_SYSTEM":        {"darkgreen"},
		"PKG_MERGE_WORLD":         {"green"},
		"PKG_BINARY_MERGE":        {"purple"},
		"PKG_BINARY_MERGE_SYSTEM": {"purple"},
		"PKG_BINARY_MERGE_WORLD":  {"fuchsia"},
		"PKG_UNINSTALL":           {"red"},
		"PKG_NOMERGE":             {"darkblue"},
		"PKG_NOMERGE_SYSTEM":      {"darkblue"},
		"PKG_NOMERGE_WORLD":       {"blue"},
		"PROMPT_CHOICE_DEFAULT":   {"green"},
		"PROMPT_CHOICE_OTHER":     {"red"},
	}
	escSeq = "\x1b["
	codes  = map[string]string{
		"normal": escSeq + "0m", "reset": escSeq + "39;49;00m",
		"bold": escSeq + "01m", "faint": escSeq + "02m",
		"standout": escSeq + "03m", "underline": escSeq + "04m",
		"blink": escSeq + "05m", "overline": escSeq + "06m",
		"reverse": escSeq + "07m", "invisible": escSeq + "08m",
		"no-attr": escSeq + "22m", "no-standout": escSeq + "23m",
		"no-underline": escSeq + "24m", "no-blink": escSeq + "25m",
		"no-overline": escSeq + "26m", "no-reverse": escSeq + "27m",
		"bg_black": escSeq + "40m", "bg_darkred": escSeq + "41m",
		"bg_darkgreen": escSeq + "42m", "bg_brown": escSeq + "43m",
		"bg_darkblue": escSeq + "44m", "bg_purple": escSeq + "45m",
		"bg_teal": escSeq + "46m", "bg_lightgray": escSeq + "47m",
		"bg_default": escSeq + "49m", "bg_darkyellow": escSeq + "43m",
	}
	ansiCodes = []string{}

	rgb_ansi_colors = []string{"0x000000", "0x555555", "0xAA0000", "0xFF5555", "0x00AA00",
		"0x55FF55", "0xAA5500", "0xFFFF55", "0x0000AA", "0x5555FF", "0xAA00AA",
		"0xFF55FF", "0x00AAAA", "0x55FFFF", "0xAAAAAA", "0xFFFFFF"}
)

func color(fg, bg string, attr []string) string {
	myStr := codes[fg]
	for _, x := range append([]string{bg}, attr...) {
		myStr += codes[x]
	}
	return myStr
}

func parseColorMap(configRoot string, onerror func(error) error) error { // /n
	myfile := path.Join(configRoot, ColorMapFile)
	ansiCodePattern := regexp.MustCompile("^[0-9;]*m$")
	quotes := "'\""
	stripQuotes := func(token string) string {
		if strings.Contains(quotes, token[:1]) && token[0] == token[len(token)-1] {
			token = token[1 : len(token)-1]

		}
		return token
	}

	f, err := os.Open(myfile)
	if err != nil {
		return err
	}
	fl, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}
	lines := strings.Split(string(fl), "\n")

	for lineno, line := range lines {
		commenterPos := strings.Index(line, "#")
		line = strings.TrimSpace(line[:commenterPos])
		if len(line) == 0 {
			continue
		}

		splitLine := strings.Split(line, "=")
		var e error
		if len(splitLine) != 2 {
			e = fmt.Errorf("'%s', line %v: expected exactly one occurrence of '=' operator", myfile, lineno)
			if onerror != nil {
				if err := onerror(e); err != nil {
					return err
				}
			} else {
				return e
			}
			continue
		}

		k := stripQuotes(strings.TrimSpace(splitLine[0]))
		v := stripQuotes(strings.TrimSpace(splitLine[1]))
		_, ok1 := styles[k]
		_, ok2 := codes[k]
		if !ok1 && !ok2 {
			e = fmt.Errorf("'%s', line %v: Unknown variable: '%s'", myfile, lineno, k)
			if onerror != nil {
				if err := onerror(e); err != nil {
					return err
				}
			} else {
				return e
			}
			continue
		}
		if ansiCodePattern.MatchString(v) {
			if _, ok := styles[k]; ok {
				styles[k] = []string{escSeq + v}
			} else if _, ok := codes[k]; ok {
				codes[k] = escSeq + v
			}
		} else {
			codeList := []string{}
			for _, x := range strings.Fields(v) {
				if _, ok := codes[x]; ok {
					if _, ok := styles[k]; ok {
						codeList = append(codeList, x)
					} else if _, ok := codes[k]; ok {
						codeList = append(codeList, codes[x])
					}
				} else {
					e = fmt.Errorf("'%s', line %v: Undefined: '%s'", myfile, lineno, x)
					if onerror != nil {
						if err := onerror(e); err != nil {
							return err
						}
					} else {
						return e
					}
				}
			}
			if _, ok := styles[k]; ok {
				styles[k] = codeList
			} else if _, ok := codes[k]; ok {
				codes[k] = strings.Join(codeList, "")
			}
		}
	}
	return nil
}

func nc_len(mystr string) int {
	re, _ := regexp.Compile(escSeq + "^m]+m")
	tmp := re.ReplaceAllString(mystr, "")
	return len(tmp)
}

var (
	_legal_terms_re, _        = regexp.Compile("^(xterm|xterm-color|Eterm|aterm|rxvt|screen|kterm|rxvt-unicode|gnome|interix|tmux|st-256color)")
	_disable_xtermTitle *bool = nil
	_max_xtermTitle_len       = 253
)

func XtermTitle(mystr string, raw bool) { // false
	if _disable_xtermTitle == nil {
		_disable_xtermTitle = new(bool)
		ts, tb := os.LookupEnv("TERM")
		*_disable_xtermTitle = !(terminal.IsTerminal(int(os.Stderr.Fd())) && tb && _legal_terms_re.MatchString(ts))
	}

	if doTitles != 0 && !*_disable_xtermTitle {
		if len(mystr) > _max_xtermTitle_len {
			mystr = mystr[:_max_xtermTitle_len]
		}
		if !raw {
			mystr = fmt.Sprintf("\x1b]0;%s\x07", mystr)
		}
		f := os.Stderr
		f.WriteString(mystr)
	}
}

var default_xterm_title = ""

func xtermTitleReset() {
	if default_xterm_title == "" {
		promptCommand := os.Getenv("PROMPT_COMMAND")
		if promptCommand == "" {
			default_xterm_title = ""
		} else if promptCommand != "" {
			ts, tb := os.LookupEnv("TERM")
			if doTitles != 0 && tb && _legal_terms_re.MatchString(ts) && terminal.IsTerminal(int(os.Stderr.Fd())) {
				shell := os.Getenv("SHELL")
				st, _ := os.Stat(shell)
				if shell == "" || st.Mode()&syscall.O_EXCL != 0 {
					shell = FindBinary("sh")
				}
				if shell != "" {
					spawn([]string{shell, "-c", promptCommand}, nil, "", map[int]uintptr{
						0: getStdin().Fd(),
						1: os.Stderr.Fd(),
						2: os.Stderr.Fd(),
					}, false, 0, 0, nil, 0, "", "", true, nil, false, false, false, false, false, "")
				} else {
					c := exec.Command(promptCommand)
					c.Run()
				}
			}
			return
		} else {
			pwd := os.Getenv("PWD")
			home := os.Getenv("HOME")
			if home != "" && strings.HasPrefix(pwd, home) {
				pwd = "~" + pwd[len(home):]
			}
			default_xterm_title = fmt.Sprintf("\x1b]0;%s@%s:%s\x07",
				os.Getenv("LOGNAME"),
				strings.SplitN(os.Getenv("HOSTNAME"), ".", 1)[0], pwd)
		}
	}
	XtermTitle(default_xterm_title, true)
}

func noTitles() {
	doTitles = 0
}

func NoColor() {
	HaveColor = 0
}

func resetColor() string {
	return codes["reset"]
}

func styleToAnsiCode(style string) string {
	ret := ""
	for _, attrName := range styles[style] {
		r, ok := codes[attrName]
		if !ok {
			ret = attrName
		} else {
			ret = r
		}
	}
	return ret
}

func ColorMap() string {
	mycolors := []string{}
	for _, c := range []string{"GOOD", "WARN", "BAD", "HILITE", "BRACKET", "NORMAL"} {
		mycolors = append(mycolors, fmt.Sprintf("%s=$'%s'", c, styleToAnsiCode(c)))
	}
	return strings.Join(mycolors, "\n")
}

func colorize(color_key, text string) string {
	if HaveColor != 0 {
		if _, ok := codes[color_key]; ok {
			return codes[color_key] + text + codes["reset"]
		} else if _, ok := styles[color_key]; ok {
			return styleToAnsiCode(color_key) + text + codes["reset"]
		} else {
			return text
		}
	} else {
		return text
	}
}

var compat_functions_colors = []string{
	"bold", "white", "teal", "turquoise", "darkteal",
	"fuchsia", "purple", "blue", "darkblue", "green", "darkgreen", "yellow",
	"brown", "darkyellow", "red", "darkred",
}

type create_color_func struct {
	colorKey string
}

func (c *create_color_func) call(text string) string {
	return colorize(c.colorKey, text)
}

func NewCreateColorFunc(colorKey string) *create_color_func {
	return &create_color_func{colorKey: colorKey}
}

var Bold = func(text string) string { return colorize("bold", text) }
var White = func(text string) string { return colorize("white", text) }
var Teal = func(text string) string { return colorize("teal", text) }
var Turquoise = func(text string) string { return colorize("turquoise", text) }
var Darkteal = func(text string) string { return colorize("darkteal", text) }
var Fuchsia = func(text string) string { return colorize("fuschia", text) }
var Purple = func(text string) string { return colorize("purple", text) }
var Blue = func(text string) string { return colorize("blue", text) }
var Green = func(text string) string { return colorize("green", text) }
var Red = func(text string) string { return colorize("red", text) }

type consoleStyleFile struct {
	_file, _styles, write_listener string
}

func NewConsoleStylefile(f string) *consoleStyleFile {
	c := &consoleStyleFile{_file: f}
	return c
}

func (c *consoleStyleFile) new_styles() {}

func (c *consoleStyleFile) write() {}

func (c *consoleStyleFile) _write() {}

func (c *consoleStyleFile) writelines() {}

func (c *consoleStyleFile) flush() {}

func (c *consoleStyleFile) close() {}

func get_term_size(fd int) (int, int, error) { // 0
	if fd == 0 {
		fd = syscall.Stdout
	}
	if !terminal.IsTerminal(fd) {
		return 0, 0, nil
	}
	return terminal.GetSize(fd)
}

func set_term_size(lines, columns, fd int) error {
	_, err := spawn([]string{"stty", "rows", string(lines), "columns", string(columns)}, nil, "", map[int]uintptr{0: uintptr(fd)}, false, 0, 0, nil, 0, "", "", true, nil, false, false, false, false, false, "")
	return err
}

type eOutput struct {
	__last_e_cmd               string
	__last_e_len, term_columns int
	quiet                      bool
}

func NewEOutput(quiet bool) *eOutput { // false
	e := &eOutput{}
	e.__last_e_cmd = ""
	e.__last_e_len = 0
	e.quiet = quiet
	_, columns, _ := get_term_size(0)
	if columns <= 0 {
		columns = 80
	}
	e.term_columns = columns
	return e
}

func (e *eOutput) _write(f *os.File, s string) {
	WriteMsg(s, -1, f)
}

func (e *eOutput) __eend(caller string, errno int, msg string) {
	status_brackets := ""
	if errno == 0 {
		status_brackets = colorize("BRACKET", "[ ") + colorize("GOOD", "ok") + colorize("BRACKET", " ]")
	} else {
		status_brackets = colorize("BRACKET", "[ ") + colorize("BAD", "!!") + colorize("BRACKET", " ]")
		if msg != "" {
			if caller == "eend" {
				e.eerror(msg[:1])
			} else if caller == "ewend" {
				e.ewarn(msg[:1])
			}
		}
	}
	if e.__last_e_cmd != "ebegin" {
		e.__last_e_len = 0
	}
	if !e.quiet {
		out := os.Stdout
		e._write(out,
			fmt.Sprintf("%*s%s\n", e.term_columns-e.__last_e_len-7,
				"", status_brackets))
	}
}

func (e *eOutput) ebegin(msg string) {
	msg += " ..."
	if !e.quiet {
		e.einfon(msg)
	}
	e.__last_e_len = len(msg) + 3
	e.__last_e_cmd = "ebegin"
}

func (e *eOutput) eend(errno int, msg string) {
	if !e.quiet {
		e.__eend("eend", errno, msg)
	}
	e.__last_e_cmd = "eend"
}

func (e *eOutput) eerror(msg string) {
	out := os.Stderr
	if !e.quiet {
		if e.__last_e_cmd == "ebegin" {
			e._write(out, "\n")
		}
		e._write(out, colorize("BAD", " * ")+msg+"\n")
	}
	e.__last_e_cmd = "eerror"
}

func (e *eOutput) einfo(msg string) {
	out := os.Stderr
	if !e.quiet {
		if e.__last_e_cmd == "ebegin" {
			e._write(out, "\n")
		}
		e._write(out, colorize("GOOD", " * ")+msg+"\n")
	}
	e.__last_e_cmd = "einfo"
}

func (e *eOutput) einfon(msg string) {
	out := os.Stderr
	if !e.quiet {
		if e.__last_e_cmd == "ebegin" {
			e._write(out, "\n")
		}
		e._write(out, colorize("GOOD", " * ")+msg)
	}
	e.__last_e_cmd = "einfon"
}

func (e *eOutput) ewarn(msg string) {
	out := os.Stderr
	if !e.quiet {
		if e.__last_e_cmd == "ebegin" {
			e._write(out, "\n")
		}
		e._write(out, colorize("WARN", " * ")+msg+"\n")
	}
	e.__last_e_cmd = "ewarn"
}

func (e *eOutput) ewend(errno int, msg string) {
	if !e.quiet {
		e.__eend("ewend", errno, msg)
	}
	e.__last_e_cmd = "ewend"
}

func init() {
	for x := 30; x < 38; x++ {
		ansiCodes = append(ansiCodes, fmt.Sprintf("%vm", x))
		ansiCodes = append(ansiCodes, fmt.Sprintf("%v;01m", x))
	}
	for k, v := range rgb_ansi_colors {
		codes[v] = escSeq + ansiCodes[k]
	}

	codes["black"] = codes["0x000000"]
	codes["darkgray"] = codes["0x555555"]

	codes["red"] = codes["0xFF5555"]
	codes["darkred"] = codes["0xAA0000"]

	codes["green"] = codes["0x55FF55"]
	codes["darkgreen"] = codes["0x00AA00"]

	codes["yellow"] = codes["0xFFFF55"]
	codes["brown"] = codes["0xAA5500"]

	codes["blue"] = codes["0x5555FF"]
	codes["darkblue"] = codes["0x0000AA"]

	codes["fuchsia"] = codes["0xFF55FF"]
	codes["purple"] = codes["0xAA00AA"]

	codes["turquoise"] = codes["0x55FFFF"]
	codes["teal"] = codes["0x00AAAA"]

	codes["white"] = codes["0xFFFFFF"]
	codes["lightgray"] = codes["0xAAAAAA"]

	codes["darkteal"] = codes["turquoise"]
	codes["0xAAAA00"] = codes["brown"]
	codes["darkyellow"] = codes["0xAAAA00"]
}

type AbstractFormatter struct {
	Writer     *bufio.Writer
	StyleStack []string
	HardBreak  bool
}

func (a *AbstractFormatter) SendLineBreak() {
	a.Writer.Write([]byte("\n"))
}
func (a *AbstractFormatter) SendLiteralData(s string) {
	a.Writer.Write([]byte(s))
}
func (a *AbstractFormatter) PushStyle(ss []string) {
	a.StyleStack = append(a.StyleStack, ss...)
}
func (a *AbstractFormatter) PopStyle(s string) {
	a.Writer.Write([]byte(s))
}

type StyleWriter struct {
	File          *os.File
	StyleListener []string
}

func (d *StyleWriter) Flush() {
}
func (d *StyleWriter) SendLineBreak() {
	d.File.Write([]byte("\n"))
}
func (d *StyleWriter) SendLiteralData(s string) {
	d.File.Write([]byte(s))
}
func (d *StyleWriter) NewStyles(s string) {
	d.File.Write([]byte(s))
}

var _color_map_loaded = false

func output_init(config_root string) { // /
	if _color_map_loaded {
		return
	}
	_color_map_loaded = true
	if err := parseColorMap(config_root, func(e error) error {
		WriteMsg(fmt.Sprintf("%s\n", e.Error()), -1, nil)
		return nil
	}); err != nil {
		return
	}
}
