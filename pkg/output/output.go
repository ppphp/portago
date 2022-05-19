package output

import (
	"bufio"
	"fmt"
	"github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/process"
	"github.com/ppphp/portago/pkg/util"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"syscall"

	terminal "golang.org/x/term"
)

const (
	escSeq = "\x1b["
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
	codes = map[string]string{
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
	ansiCodes = []string{"30m", "30;01m", "31m", "31;01m",
		"32m", "32;01m", "33m", "33;01m", "34m", "34;01m",
		"35m", "35;01m", "36m", "36;01m", "37m", "37;01m"}

	rgb_ansi_colors = []string{"0x000000", "0x555555", "0xAA0000", "0xFF5555", "0x00AA00",
		"0x55FF55", "0xAA5500", "0xFFFF55", "0x0000AA", "0x5555FF", "0xAA00AA",
		"0xFF55FF", "0x00AAAA", "0x55FFFF", "0xAAAAAA", "0xFFFFFF"}
)

// "default", []string{"normal"}
func color(fg, bg string, attr []string) string {
	myStr := codes[fg]
	for _, x := range append([]string{bg}, attr...) {
		myStr += codes[x]
	}
	return myStr
}

func init() {

	for x := range rgb_ansi_colors {
		codes[rgb_ansi_colors[x]] = escSeq + ansiCodes[x]
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

// "/", nil
func parseColorMap(configRoot string, onerror func(error) error) error {
	myfile := path.Join(configRoot, _const.ColorMapFile)
	ansiCodePattern := regexp.MustCompile("^[0-9;]*m$")
	quotes := "'\""
	stripQuotes := func(token string) string {
		if strings.Contains(quotes, token[:1]) && token[0] == token[len(token)-1] {
			token = token[1 : len(token)-1]

		}
		return token
	}

	fl, err := ioutil.ReadFile(myfile)
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

// false
func XtermTitle(mystr string, raw bool) {
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
		f.Sync()
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
				st, err := os.Stat(shell)
				if shell == "" || (err != nil && st.Mode()&syscall.O_EXCL != 0) {
					shell = process.FindBinary("sh")
				}
				if shell != "" {
					process.Spawn([]string{shell, "-c", promptCommand}, nil, "", map[int]uintptr{
						0: os.Stdin.Fd(),
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

func Colorize(color_key, text string) string {
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

func NewCreateColorFunc(colorKey string) func(text string) string {
	return func(text string) string { return Colorize(colorKey, text) }
}

var Bold = func(text string) string { return Colorize("bold", text) }
var White = func(text string) string { return Colorize("white", text) }
var Teal = func(text string) string { return Colorize("teal", text) }
var Turquoise = func(text string) string { return Colorize("turquoise", text) }
var Darkteal = func(text string) string { return Colorize("darkteal", text) }
var Fuchsia = func(text string) string { return Colorize("fuschia", text) }
var Purple = func(text string) string { return Colorize("purple", text) }
var Blue = func(text string) string { return Colorize("blue", text) }
var Green = func(text string) string { return Colorize("green", text) }
var Red = func(text string) string { return Colorize("red", text) }

type consoleStyleFile struct {
	_file          io.WriteCloser
	write_listener io.Writer
	_styles        []string
}

func NewConsoleStylefile(f io.WriteCloser) *consoleStyleFile {
	c := &consoleStyleFile{_file: f}
	return c
}

func (c *consoleStyleFile) new_styles(styles []string) {
	c._styles = styles
}

func (c *consoleStyleFile) write(s string) {
	if HaveColor != 0 && len(c._styles) > 0 {
		styled_s := []string{}
		for _, style := range c._styles {
			styled_s = append(styled_s, styleToAnsiCode(style))
		}
		styled_s = append(styled_s, s)
		styled_s = append(styled_s, codes["reset"])
		c._write(c._file, strings.Join(styled_s, ""))
	} else {
		c._write(c._file, s)
	}
	if c.write_listener != nil {
		c._write(c.write_listener, s)
	}
}

func (c *consoleStyleFile) _write(f io.Writer, s string) {
	f.Write([]byte(s))
}

func (c *consoleStyleFile) writelines(lines []string) {
	for _, l := range lines {
		c.write(l)
	}
}

func (c *consoleStyleFile) flush() {
}

func (c *consoleStyleFile) close() {}

type StyleWriter struct {
	File          *os.File
	StyleListener []string
	maxcol        int
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

// 0
func get_term_size(fd int) (int, int, error) {
	if fd == 0 {
		fd = syscall.Stdout
	}
	if !terminal.IsTerminal(fd) {
		return 0, 0, nil
	}
	return terminal.GetSize(fd)
}

func set_term_size(lines, columns, fd int) error {
	_, err := process.Spawn([]string{"stty", "rows", string(lines), "columns", string(columns)}, nil, "", map[int]uintptr{0: uintptr(fd)}, false, 0, 0, nil, 0, "", "", true, nil, false, false, false, false, false, "")
	return err
}

type EOutput struct {
	__last_e_cmd               string
	__last_e_len, term_columns int
	quiet                      bool
}

// false
func NewEOutput(quiet bool) *EOutput {
	e := &EOutput{}
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

func (e *EOutput) _write(f *os.File, s string) {
	util.WriteMsg(s, -1, f)
}

func (e *EOutput) __eend(caller string, errno int, msg string) {
	status_brackets := ""
	if errno == 0 {
		status_brackets = Colorize("BRACKET", "[ ") + Colorize("GOOD", "ok") + Colorize("BRACKET", " ]")
	} else {
		status_brackets = Colorize("BRACKET", "[ ") + Colorize("BAD", "!!") + Colorize("BRACKET", " ]")
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

func (e *EOutput) Ebegin(msg string) {
	msg += " ..."
	if !e.quiet {
		e.einfon(msg)
	}
	e.__last_e_len = len(msg) + 3
	e.__last_e_cmd = "ebegin"
}

// ""
func (e *EOutput) Eend(errno int, msg string) {
	if !e.quiet {
		e.__eend("eend", errno, msg)
	}
	e.__last_e_cmd = "eend"
}

func (e *EOutput) eerror(msg string) {
	out := os.Stderr
	if !e.quiet {
		if e.__last_e_cmd == "ebegin" {
			e._write(out, "\n")
		}
		e._write(out, Colorize("BAD", " * ")+msg+"\n")
	}
	e.__last_e_cmd = "eerror"
}

func (e *EOutput) einfo(msg string) {
	out := os.Stderr
	if !e.quiet {
		if e.__last_e_cmd == "ebegin" {
			e._write(out, "\n")
		}
		e._write(out, Colorize("GOOD", " * ")+msg+"\n")
	}
	e.__last_e_cmd = "einfo"
}

func (e *EOutput) einfon(msg string) {
	out := os.Stderr
	if !e.quiet {
		if e.__last_e_cmd == "ebegin" {
			e._write(out, "\n")
		}
		e._write(out, Colorize("GOOD", " * ")+msg)
	}
	e.__last_e_cmd = "einfon"
}

func (e *EOutput) ewarn(msg string) {
	out := os.Stderr
	if !e.quiet {
		if e.__last_e_cmd == "ebegin" {
			e._write(out, "\n")
		}
		e._write(out, Colorize("WARN", " * ")+msg+"\n")
	}
	e.__last_e_cmd = "ewarn"
}

func (e *EOutput) ewend(errno int, msg string) {
	if !e.quiet {
		e.__eend("ewend", errno, msg)
	}
	e.__last_e_cmd = "ewend"
}

type ProgressBar struct {
	_title, _label, _desc              string
	_maxval, _curval, _desc_max_length int
}

func (p *ProgressBar) curval() int {
	return p._curval
}

func (p *ProgressBar) maxval() int {
	return p._maxval
}

func (p *ProgressBar) title(newstr string) {
	p._title = newstr
	p._set_desc()
}

func (p *ProgressBar) label(newstr string) {
	p._label = newstr
	p._set_desc()
}

func (p *ProgressBar) _set_desc() {
	p._desc = fmt.Sprintf("%s%s", fmt.Sprintf(
		"%s: ", p._title), fmt.Sprintf(
		"%s", p._label))

	if len(p._desc) > p._desc_max_length {
		p._desc = fmt.Sprintf("%s...", p._desc[:p._desc_max_length-3])
	}
	if len(p._desc) > 0 {
		p._desc = fmt.Sprintf("%"+fmt.Sprint(p._desc_max_length)+"s", p._desc)
	}

}

func (p *ProgressBar) set(value, maxval int) { // 0
	if maxval != 0 {
		p._maxval = maxval
	}
	if value < 0 {
		value = 0
	} else if value > p._maxval {
		value = p._maxval
	}
	p._curval = value
}

func (p *ProgressBar) inc(n int) { // 1
	p.set(p._curval+n, 0)
}

func NewProgressBar(title string, maxval int, label string, max_desc_length int) *ProgressBar { // "", 0, "", 25
	p := &ProgressBar{}
	p._title = title
	p._maxval = maxval
	p._label = label
	p._curval = 0
	p._desc = ""
	p._desc_max_length = max_desc_length
	p._set_desc()

	return p
}

type TermProgressBar struct {
	*ProgressBar
	term_columns, _min_columns, _max_columns int
	_position                                float64
	file                                     *os.File
}

func (t *TermProgressBar) set(value, maxval int) { // 0
	t.ProgressBar.set(value, maxval)
	t._display_image(t._create_image())
}

func (t *TermProgressBar) _display_image(image []byte) {
	t.file.Write([]byte("\r"))
	t.file.Write(image)
}

func (t *TermProgressBar) _create_image() []byte {
	cols := t.term_columns
	if cols > t._max_columns {
		cols = t._max_columns
	}
	min_columns := t._min_columns
	curval := t._curval
	maxval := t._maxval
	position := t._position
	percentage_str_width := 5
	square_brackets_width := 2
	if cols < percentage_str_width {
		return []byte{}
	}
	bar_space := cols - percentage_str_width - square_brackets_width - 1
	if t._desc != "" {
		bar_space -= t._desc_max_length
	}
	if maxval == 0 {
		max_bar_width := bar_space - 3
		_percent := fmt.Sprintf("%"+fmt.Sprint(percentage_str_width)+"s", "")
		if cols < min_columns {
			return []byte{}
		}
		var offset float64
		if position <= 0.5 {
			offset = 2 * position
		} else {
			offset = 2 * (1 - position)
		}
		delta := 0.5 / float64(max_bar_width)
		position += delta
		if position >= 1.0 {
			position = 0.0
		}
		if 1.0-position < delta {
			position = 1.0
		}
		if position < 0.5 && 0.5-position < delta {
			position = 0.5
		}
		t._position = position
		bar_width := int(offset * float64(max_bar_width))
		image := fmt.Sprintf("%s%s%s", t._desc, _percent,
			"["+strings.Repeat(" ", bar_width)+
				"<=>"+strings.Repeat(" ", max_bar_width-bar_width)+"]")
		return []byte(image)
	} else {
		percentage := 100 * curval // maxval
		max_bar_width := bar_space - 1
		_percent := fmt.Sprintf("%"+fmt.Sprint(percentage_str_width)+"d", fmt.Sprintf("%d%% ", percentage))
		image := fmt.Sprintf("%s%s", t._desc, _percent)

		if cols < min_columns {
			return []byte(image)
		}
		offset := curval / maxval
		bar_width := int(offset * max_bar_width)
		image = image + "[" + strings.Repeat("=", bar_width) +
			">" + strings.Repeat(" ", max_bar_width-bar_width) + "]"
		return []byte(image)
	}
}

func NewTermProgressBar(fd *os.File, title string, maxval int, label string, max_desc_length int) *TermProgressBar { // os.Stdout, "", 0, "", 25
	t := &TermProgressBar{}
	t.ProgressBar = NewProgressBar(title, maxval, label, max_desc_length)
	_, t.term_columns, _ = get_term_size(int(fd.Fd()))
	t.file = fd
	t._min_columns = 11
	t._max_columns = 80
	t._position = 0.0

	return t
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

var _color_map_loaded = false

func output_init(config_root string) { // /
	if _color_map_loaded {
		return
	}
	_color_map_loaded = true
	if err := parseColorMap(config_root, func(e error) error {
		util.WriteMsg(fmt.Sprintf("%s\n", e.Error()), -1, nil)
		return nil
	}); err != nil {
		return
	}
}
