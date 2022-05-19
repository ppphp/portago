package util

import (
	"fmt"
	"github.com/ppphp/portago/atom"
	"github.com/ppphp/portago/pkg/checksum"
	"github.com/ppphp/portago/pkg/data"
	"github.com/ppphp/portago/pkg/dbapi"
	"github.com/ppphp/portago/pkg/ebuild"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/portage"
	"github.com/ppphp/portago/pkg/process"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
)

// 1, "", nil, nil, nil, nil, nil
func env_update(makelinks int, target_root string, prev_mtimes=None, contents map[string][]string,
	env *ebuild.Config, writemsg_level func(string, int, int), vardbapi *atom.vardbapi) {
	if vardbapi == nil {
		vardbapi = dbapi.NewVarTree(nil, env).dbapi
	}

	vardbapi._fs_lock()
	defer vardbapi._fs_unlock()
	_env_update(makelinks, target_root, prev_mtimes, contents,
		env, writemsg_level)
}

func _env_update(makelinks int, target_root string, prev_mtimes map[string]int, contents map[string][]string, envC *ebuild.Config,
	writemsg_level func(string, int, int)) {
	if writemsg_level == nil {
		writemsg_level = WriteMsgLevel
	}
	if target_root == "" {
		target_root = portage.Settings().ValueDict["ROOT"]
	}
	if prev_mtimes == nil {
		prev_mtimes = portage.mtimedb["ldpath"]
	}
	var settings *ebuild.Config
	if envC == nil {
		settings = portage.Settings()
	} else {
		settings = envC
	}

	eprefix := settings.ValueDict["EPREFIX"]
	eprefix_lstrip := strings.TrimLeft(eprefix, string(os.PathSeparator))
	eroot := strings.TrimRight(NormalizePath(filepath.Join(target_root, eprefix_lstrip)), string(os.PathSeparator)) + string(os.PathSeparator)
	envd_dir := filepath.Join(eroot, "etc", "env.d")
	ensureDirs(envd_dir, -1, -1, 0755, -1, nil, true)
	fns := listdir(envd_dir, false, false, false, []string{}, true, true, false)
	sort.Strings(fns)
	templist := []string{}
	for _, x := range fns {
		if len(x) < 3 {
			continue
		}
		if !unicode.IsDigit(rune(x[0])) || !unicode.IsDigit(rune(x[1])) {
			continue
		}
		if strings.HasPrefix(x, ".") || strings.HasSuffix(x, "~") || strings.HasSuffix(x, ".bak") {
			continue
		}
		templist = append(templist, x)
	}
	fns = templist

	templist = nil

	space_separated := map[string]bool{"CONFIG_PROTECT": true, "CONFIG_PROTECT_MASK": true}
	colon_separated := map[string]bool{"ADA_INCLUDE_PATH": true, "ADA_OBJECTS_PATH": true,
		"CLASSPATH": true, "INFODIR": true, "INFOPATH": true, "KDEDIRS": true, "LDPATH": true, "MANPATH": true,
		"PATH": true, "PKG_CONFIG_PATH": true, "PRELINK_PATH": true, "PRELINK_PATH_MASK": true,
		"PYTHONPATH": true, "ROOTPATH": true}

	config_list := []map[string]string{}

	for _, x := range fns {
		file_path := filepath.Join(envd_dir, x)
		//try:
		myconfig := getConfig(file_path, false, false, false, false, nil)
		//except ParseError as e:
		//writemsg("!!! '%s'\n"%str(e), noiselevel = -1)
		//del e
		//continue
		if myconfig == nil {
			WriteMsg(fmt.Sprintf("!!! File Not Found: '%s'\n", file_path), -1, nil)
			continue
		}

		config_list = append(config_list, myconfig)
		if myutil.Inmss(myconfig, "SPACE_SEPARATED") {
			for _, v := range strings.Fields(myconfig["SPACE_SEPARATED"]) {
				space_separated[v] = true
			}
			delete(myconfig, "SPACE_SEPARATED")
		}
		if myutil.Inmss(myconfig, "COLON_SEPARATED") {
			for _, v := range strings.Fields(myconfig["COLON_SEPARATED"]) {
				colon_separated[v] = true
			}
			delete(myconfig, "COLON_SEPARATED")
		}
	}

	env := map[string]string{}
	specials := map[string][]string{}
	for v := range space_separated {
		mylist := []string{}
		for _, myconfig := range config_list {
			if myutil.Inmss(myconfig, v) {
				for _, item := range strings.Fields(myconfig[v]) {
					if item != "" && !myutil.Ins(mylist, item) {
						mylist = append(mylist, item)
					}
				}
				delete(myconfig, v)
			}
		}
		if len(mylist) > 0 {
			env[v] = strings.Join(mylist, " ")
			specials[v] = mylist
		}
	}

	env := map[string]string{}
	specials := map[string][]string{}
	for v := range colon_separated {
		mylist := []string{}
		for _, myconfig := range config_list {
			if myutil.Inmss(myconfig, v) {
				for _, item := range strings.Fields(myconfig[v]) {
					if item != "" && !myutil.Ins(mylist, item) {
						mylist = append(mylist, item)
					}
				}
				delete(myconfig, v)
			}
		}
		if len(mylist) > 0 {
			env[v] = strings.Join(mylist, " ")
			specials[v] = mylist
		}
	}

	for _, myconfig := range config_list {
		for k, v := range myconfig {
			env[k] = v
		}
	}

	ldsoconf_path := filepath.Join(eroot, "etc", "ld.so.conf")

	oldld := []string{}
	myld, err := ioutil.ReadFile(ldsoconf_path)
	if err == nil {
		myldlines := strings.Split(string(myld), "\n")
		for _, x := range myldlines {
			if x[:1] == "#" {
				continue
			}
			oldld = append(oldld, x[:len(x)-1])
		}
	} else {
		//except (IOError, OSError) as e:
		if err != syscall.ENOENT {
			//raise
		}
	}

	newld := specials["LDPATH"]
	if len(oldld) != len(newld) {
		eq := true
		for i := range oldld {
			if oldld[i] != newld[i] {
				eq = false
				break
			}
		}
		if eq {
			myfd := NewAtomic_ofstream(ldsoconf_path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, true)
			myfd.Write([]byte("# ld.so.conf autogenerated by env-update; make all changes to\n"))
			myfd.Write([]byte("# contents of /etc/env.d directory\n"))
			for _, x := range specials["LDPATH"] {
				myfd.Write([]byte(x + "\n"))
			}
			myfd.Close()
		}
	}

	potential_lib_dirs := map[string]bool{}
	for _, lib_dir_glob := range []string{"usr/lib*", "lib*"} {
		x := filepath.Join(eroot, lib_dir_glob)
		glb, _ := filepath.Glob(x)
		for _, y := range glb {
			if filepath.Base(y) != "libexec" {
				potential_lib_dirs[y[len(eroot):]] = true
			}
		}
	}

	if checksum.PrelinkCapable {
		prelink_d := filepath.Join(eroot, "etc", "prelink.conf.d")
		ensureDirs(prelink_d, -1, -1, -1, -1, nil, true)
		newprelink := NewAtomic_ofstream(filepath.Join(prelink_d, "portage.conf"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, true)
		newprelink.Write([]byte("# prelink.conf autogenerated by env-update; make all changes to\n"))
		newprelink.Write([]byte("# contents of /etc/env.d directory\n"))

		for _, x := range append(myutil.Sortedmsb(potential_lib_dirs), "bin", "sbin") {
			newprelink.Write([]byte(fmt.Sprintf("-l /%s\n", x, )))
		}
		prelink_paths := map[string]bool{}
		for _, v := range specials["LDPATH"] {
			prelink_paths[v] = true
		}
		for _, v := range specials["PATH"] {
			prelink_paths[v] = true
		}
		for _, v := range specials["PRELINK_PATH"] {
			prelink_paths[v] = true
		}
		prelink_path_mask := specials["PRELINK_PATH_MASK"]
		for x := range prelink_paths {
			if x == "" {
				continue
			}
			if x[len(x)-1:] != "/" {
				x += "/"
			}
			plmasked := 0
			for _, y := range prelink_path_mask {
				if y == "" {
					continue
				}
				if y[len(y)-1] != '/' {
					y += "/"
				}
				if y == x[0:len(y)] {
					plmasked = 1
					break
				}
			}
			if plmasked == 0 {
				newprelink.Write([]byte(fmt.Sprintf("-h %s\n", x, )))
			}
		}
		for _, x := range prelink_path_mask {
			newprelink.Write([]byte(fmt.Sprintf("-b %s\n", x, )))
		}
		newprelink.Close()

		prelink_conf := filepath.Join(eroot, "etc", "prelink.conf")

		f, err := ioutil.ReadFile(prelink_conf)
		if err != syscall.ENOENT {
			//raise
		}
		if strings.Split(string(f), "\n")[0] == "# prelink.conf autogenerated by env-update; make all changes to\\n" {

			f := NewAtomic_ofstream(prelink_conf, os.O_RDWR|os.O_CREATE|os.O_TRUNC, true)
			f.Write([]byte("-c /etc/prelink.conf.d/*.conf\n"))
			f.Close()
		}
	}

	current_time := time.Now().Nanosecond()
	mtime_changed := false

	lib_dirs := map[string]bool{}
	spld := map[string]bool{}
	for _, k := range specials["LD_PATH"] {
		spld[k] = true
	}
	for k := range potential_lib_dirs {
		spld[k] = true
	}

	for lib_dir := range spld {
		x := filepath.Join(eroot, strings.TrimLeft(lib_dir, string(os.PathSeparator)))
		st, err := os.Stat(x)
		if err != nil {
			//except OSError as oe:
			if err == syscall.ENOENT {
				delete(prev_mtimes, x)
				continue
			}
			//raise
		} else {
			lib_dirs[NormalizePath(x)] = true
		}
		newldpathtime := st.ModTime().Nanosecond()
		if newldpathtime == current_time {
			newldpathtime -= 1
			syscall.Utime(x, &syscall.Utimbuf{int64(newldpathtime), int64(newldpathtime)})
			prev_mtimes[x] = newldpathtime
			mtime_changed = true
		} else if _, ok := prev_mtimes[x]; ok {
			if prev_mtimes[x] == newldpathtime {
				//pass
			} else {
				prev_mtimes[x] = newldpathtime
				mtime_changed = true
			}
		} else {
			prev_mtimes[x] = newldpathtime
			mtime_changed = true
		}
	}

	if makelinks != 0 && !mtime_changed && contents != nil {
		libdir_contents_changed := false
		for mypath, mydata := range contents {
			if mydata[0] != "obj" && mydata[0] != "sym" {
				continue
			}
			head, _ := filepath.Split(mypath)
			if lib_dirs[head] {
				libdir_contents_changed = true
				break
			}
		}
		if !libdir_contents_changed {
			makelinks = 0
		}
	}

	ldconfig := ""
	if myutil.Inmss(settings.ValueDict, "CHOST") && myutil.Inmss(settings.ValueDict, "CBUILD") && settings.ValueDict["CHOST"] != settings.ValueDict["CBUILD"] {
		ldconfig = process.FindBinary(fmt.Sprintf("%s-ldconfig", settings.ValueDict["CHOST"]))
	} else {
		ldconfig = filepath.Join(eroot, "sbin", "ldconfig")
	}

	if ldconfig == "" {
		//pass
	} else if !(myutil.OsAccess(ldconfig, unix.X_OK) && myutil.PathIsFile(ldconfig)) {
		ldconfig = ""
	}

	if makelinks != 0 && ldconfig != "" {
		if data.Ostype == "Linux" || strings.HasSuffix(strings.ToLower(data.Ostype), "gnu") {
			writemsg_level(fmt.Sprintf(">>> Regenerating %setc/ld.so.cache...\n",
				target_root, ), 0, 0)
			exec.Command("sh", "-c", fmt.Sprintf("cd / ; %s -X -r '%s'", ldconfig, target_root))
		} else if data.Ostype == "FreeBSD" || data.Ostype == "DragonFly" {
			writemsg_level(fmt.Sprintf(">>> Regenerating %svar/run/ld-elf.so.hints...\n",
				target_root), 0, 0)
			exec.Command("sh", "-c", fmt.Sprintf("cd / ; %s -elf -i "+
				"-f '%svar/run/ld-elf.so.hints' '%setc/ld.so.conf'", ldconfig, target_root, target_root))
		}
	}

	delete(specials, "LDPATH")

	penvnotice := "# THIS FILE IS AUTOMATICALLY GENERATED BY env-update.\n"
	penvnotice += "# DO NOT EDIT THIS FILE. CHANGES TO STARTUP PROFILES\n"
	cenvnotice := penvnotice[:]
	penvnotice += "# GO INTO /etc/profile NOT /etc/profile.env\n\n"
	cenvnotice += "# GO INTO /etc/csh.cshrc NOT /etc/csh.env\n\n"

	outfile := NewAtomic_ofstream(filepath.Join(eroot, "etc", "profile.env"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, true)
	outfile.Write([]byte(penvnotice))
	env_keys := []string{}
	for x := range env {
		if x != "LDPATH" {
			env_keys = append(env_keys, x)
		}
	}
	sort.Strings(env_keys)
	for _, k := range env_keys {
		v := env[k]
		if strings.HasPrefix(v, "$") && !strings.HasPrefix(v, "${") {
			outfile.Write([]byte(fmt.Sprintf("export %s=$'%s'\n", k, v[1:])))
		} else {
			outfile.Write([]byte(fmt.Sprintf("export %s='%s'\n", k, v)))
		}
	}
	outfile.Close()

	outfile = NewAtomic_ofstream(filepath.Join(eroot, "etc", "csh.env"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, true)
	outfile.Write([]byte(cenvnotice))
	for _, x := range env_keys {
		outfile.Write([]byte(fmt.Sprintf("setenv %s '%s'\n", x, env[x])))
	}
	outfile.Close()
}
