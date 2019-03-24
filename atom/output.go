package atom

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
)

var (
	haveColor = 1
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

var havecolor = 1

func NoColor() {
	havecolor = 0
}

func noTitles() {
	doTitles = 0
}

func resetColor() string {
	return codes["reset"]
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
			e = fmt.Errorf("'%s', line %s: expected exactly one occurrence of '=' operator", myfile, lineno)
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
			e = fmt.Errorf("'%s', line %s: Unknown variable: '%s'", myfile, lineno, k)
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
					e = fmt.Errorf("'%s', line %s: Undefined: '%s'", myfile, lineno, x)
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
	if haveColor != 0 {
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
