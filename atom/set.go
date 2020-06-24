package atom

import (
	"fmt"
	"github.com/ppphp/configparser"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
)

const SETPREFIX = "@"

func get_boolean(options map[string]string, name string, defaultt bool) bool {
	if _, ok := options[name]; !ok{
		return defaultt
	} else if  Ins([]string{"1", "yes", "on", "true"}, strings.ToLower(options[name])) {
		return true
	} else if Ins([]string{"0", "no", "off", "false"}, strings.ToLower(options[name])) {
		return false
	} else {
		//raise SetConfigError(_("invalid value '%(value)s' for option '%(option)s'") %
		//{"value": options[name], "option": name})
		return false
	}
}

type SetConfigError struct {
	error
}

type SetConfig struct {
	_parsed  bool
	trees    *Tree
	settings *Config
	psets    map[string]string
	errors, active   []string

	_parser configparser.ConfigParser
}

func (s*SetConfig)_create_default_config() {
	parser := s._parser

	delete(parser.GetSectionMap(),"world")
	parser.GetSectionMap()["world"]= map[string]string{}
	parser.GetSectionMap()["world"]["class"] = "portage.sets.base.DummyPackageSet"
	parser.GetSectionMap()["world"]["packages"] = "@profile @selected @system"

	delete(parser.GetSectionMap(),"profile")
	parser.GetSectionMap()["profile"]= map[string]string{}
	parser.GetSectionMap()["profile"]["class"] = "portage.sets.ProfilePackageSet.ProfilePackageSet"

	delete(parser.GetSectionMap(),"selected")
	parser.GetSectionMap()["selected"]= map[string]string{}
	parser.GetSectionMap()["selected"]["class"] = "portage.sets.files.WorldSelectedSet"

	delete(parser.GetSectionMap(),"selected-packages")
	parser.GetSectionMap()["selected-packages"]= map[string]string{}
	parser.GetSectionMap()["selected-packages"]["class"] = "portage.sets.files.WorldSelectedPackagesSet"

	delete(parser.GetSectionMap(),"selected-sets")
	parser.GetSectionMap()["selected-sets"]= map[string]string{}
	parser.GetSectionMap()["selected-sets"]["class"] = "portage.sets.files.WorldSelectedSetsSet"

	delete(parser.GetSectionMap(),"system")
	parser.GetSectionMap()["system"]= map[string]string{}
	parser.GetSectionMap()["system"]["class"] = "portage.sets.profiles.PackagesSystemSet"

	delete(parser.GetSectionMap(),"security")
	parser.GetSectionMap()["security"]= map[string]string{}
	parser.GetSectionMap()["security"]["class"] = "portage.sets.security.NewAffectedSet"

	delete(parser.GetSectionMap(),"usersets")
	parser.GetSectionMap()["usersets"]= map[string]string{}
	parser.GetSectionMap()["usersets"]["class"] = "portage.sets.files.StaticFileSet"
	parser.GetSectionMap()["usersets"]["multiset"] = "true"
	parser.GetSectionMap()["usersets"]["directory"] = "%(PORTAGE_CONFIGROOT)setc/portage/sets"
	parser.GetSectionMap()["usersets"]["world-candidate"] = "true"

	delete(parser.GetSectionMap(),"live-rebuild")
	parser.GetSectionMap()["live-rebuild"]= map[string]string{}
	parser.GetSectionMap()["live-rebuild"]["class"] = "portage.sets.dbapi.VariableSet"
	parser.GetSectionMap()["live-rebuild"]["variable"] = "PROPERTIES"
	parser.GetSectionMap()["live-rebuild"]["includes"] = "live"

	delete(parser.GetSectionMap(),"deprecated-live-rebuild")
	parser.GetSectionMap()["deprecated-live-rebuild"]= map[string]string{}
	parser.GetSectionMap()["deprecated-live-rebuild"]["class"] = "portage.sets.dbapi.VariableSet"
	parser.GetSectionMap()["deprecated-live-rebuild"]["variable"] = "INHERITED"
	le := []string{}
	for k := range LIVE_ECLASSES{
		le = append(le, k)
	}
	parser.GetSectionMap()["deprecated-live-rebuild"]["includes"] = strings.Join(sorted(le), " ")

	delete(parser.GetSectionMap(),"module-rebuild")
	parser.GetSectionMap()["module-rebuild"]= map[string]string{}
	parser.GetSectionMap()["module-rebuild"]["class"] = "portage.sets.dbapi.OwnerSet"
	parser.GetSectionMap()["module-rebuild"]["files"] = "/lib/modules"

	delete(parser.GetSectionMap(),"preserved-rebuild")
	parser.GetSectionMap()["preserved-rebuild"]= map[string]string{}
	parser.GetSectionMap()["preserved-rebuild"]["class"] = "portage.sets.libs.PreservedLibraryConsumerSet"

	delete(parser.GetSectionMap(),"x11-module-rebuild")
	parser.GetSectionMap()["x11-module-rebuild"]= map[string]string{}
	parser.GetSectionMap()["x11-module-rebuild"]["class"] = "portage.sets.dbapi.OwnerSet"
	parser.GetSectionMap()["x11-module-rebuild"]["files"] = "/usr/lib*/xorg/modules"
	parser.GetSectionMap()["x11-module-rebuild"]["exclude-files"] = "/usr/bin/Xorg"
}

func (s*SetConfig) update(setname string, options map[string]string) {
	parser := s._parser
	s.errors = []string{}
	if _, ok := s.psets[setname]; !ok {
		options["name"] = setname
		options["world-candidate"] = "False"

		for Ins(parser.Sections(), setname) {
			setname = fmt.Sprintf("%08d", rand.Int63n(10000000000))
		}

		parser.GetSectionMap()[setname] = map[string]string{}
		for k, v := range options {
			parser.GetSectionMap()[setname][k] = v
		}
	} else {
		section := s.psets[setname].creator
		if parser.HasOption(section, "multiset") &&
			parser.GetSectionMap()[section]["multiset"] == "true" {
			s.errors = append(s.errors, fmt.Sprintf("Invalid request to reconfigure set '%s' generated "+
				"by multiset section '%s'", setname, section))
			return
		}
		for k, v := range options {
			parser.GetSectionMap()[section][k] = v
		}
	}
	s._parse(true)
}

// false
func(s*SetConfig) _parse( update bool) {
	if s._parsed && !update {
		return
	}
	parser := s._parser
	for _, sname:= range parser.Sections() {
		classname := ""
		if ! parser.HasOption(sname, "class") {
			classname = "portage._sets.files.StaticFileSet"
		}else {
			classname, _ = parser.Gett(sname, "class")
		}

		if strings.HasPrefix(classname, "portage.sets.") {
			classname = strings.Replace(classname, "sets", "_sets", 1)
		}

	try:
		setclass = load_mod(classname)
		except(ImportError, AttributeError):
	try:
		setclass = load_mod("portage._sets." + classname)
		except(ImportError, AttributeError):
		s.errors = append(s.errors, fmt.Sprintf("Could not import '%s' for section '%s'", classname, sname))
		continue
		optdict := map[string]string{}
		for _, oname := range parser.Options(sname) {
			optdict[oname], _= parser.gett(sname, oname)
		}

		if parser.HasOption(sname, "multiset") && parser.getboolean(sname, "multiset") {
			if hasattr(setclass, "multiBuilder") {
				newsets :=map[string]string{}
			try:
				newsets = setclass.multiBuilder(optdict, s.settings, s.trees)
				except
				SetConfigError
				as
			e:
				s.errors = append(s.errors, fmt.Sprintf("Configuration error in section '%s': %s", sname, str(e)))
				continue
				for x
					in
				newsets {
					if Inmss(s.psets,x) &&!update {
						s.errors = append(s.errors, fmt.Sprintf("Redefinition of set '%s' (sections: '%s', '%s')", x, s.psets[x].creator, sname))
					}
					newsets[x].creator = sname
					if parser.HasOption(sname, "world-candidate") && parser.getboolean(sname, "world-candidate") {
						newsets[x].world_candidate = true
					}
				}
				for k, v := range newsets {
					s.psets[k]=v
				}
			}else {
				s.errors = append(s.errors, fmt.Sprintf("Section '%s' is configured as multiset, but '%s' "+
					"doesn't support that configuration", sname, classname))
				continue
			}
		}else {
			setname, err := parser.Gett(sname, "name")
			if err != nil {
				//except NoOptionError:
				setname = sname
			}
			if _, ok := s.psets[setname]; ok && !update {
				s.errors = append(s.errors, fmt.Sprintf("Redefinition of set '%s' (sections: '%s', '%s')", setname, s.psets[setname].creator, sname))
			}
			if hasattr(setclass, "singleBuilder") {
			try:
				s.psets[setname] = setclass.singleBuilder(optdict, s.settings, s.trees)
				s.psets[setname].creator = sname
				if parser.HasOption(sname, "world-candidate") &&
					parser.GetSectionMap()[sname]["world-candidate"] == "true":
				s.psets[setname].world_candidate = true
				except
				SetConfigError
				as
			e:
				s.errors = append(s.errors, fmt.Sprintf("Configuration error in section '%s': %s", sname, str(e)))
				continue
			} else {
				s.errors = append(s.errors, fmt.Sprintf("'%s' does not support individual set creation, section '%s' "+
					"must be configured as multiset", classname, sname))
				continue
			}
		}
	}
	s._parsed = true
}

func (s*SetConfig) getSets() map[string]string{
	s._parse(false)
	return CopyMapSS(s.psets)
}

// nil
func (s*SetConfig) getSetAtoms(setname string, ignorelist map[string]bool) {
	s._parse(false)
try:
	myset := s.psets[setname]
	except
KeyError:
	raise
	PackageSetNotFound(setname)
	myatoms := myset.getAtoms()

	if ignorelist == nil {
		ignorelist = map[string]bool{}
	}

	ignorelist[setname]=true
	for n
	in
	myset.getNonAtoms() {
		if strings.HasPrefix(n, SETPREFIX) {
			s1 := n[len(SETPREFIX):]
			if _, ok := s.psets[s1]; ok {
				if !ignorelist[s1] {
					myatoms.update(s.getSetAtoms(s1,
						ignorelist))
				}
			} else {
				//raise
				//PackageSetNotFound(s)
			}
		}
	}

	return myatoms
}

func NewSetConfig(paths []string, settings *Config, trees *Tree)*SetConfig{
	s := &SetConfig{}
	agm := configparser.DefaultArgument
	agm.Defaults = map[string]string{
		"EPREFIX" : settings.ValueDict["EPREFIX"],
		"EROOT" : settings.ValueDict["EROOT"],
		"PORTAGE_CONFIGROOT" : settings.ValueDict["PORTAGE_CONFIGROOT"],
		"ROOT" : settings.ValueDict["ROOT"],
	}
	s._parser = configparser.NewConfigParser(agm)

	if enableSetConfig {
		readConfigs(s._parser, paths)
	}else {
		s._create_default_config()
	}

	s.errors = []string{}
	s.psets = map[string]string{}
	s.trees = trees
	s.settings = settings
	s._parsed = false
	s.active = []string{}
	return s
}

func LoadDefaultConfig(settings *Config, trees *Tree) *SetConfig {

	if !enableSetConfig {
		return NewSetConfig(nil, settings, trees)
	}

	global_config_path := GlobalConfigPath
	if EPREFIX != "" {
		global_config_path = filepath.Join(EPREFIX,
			strings.TrimLeft(GlobalConfigPath, string(os.PathSeparator)))
	}
	vcs_dirs := CopyMapSB(VcsDirs)
	_getfiles := func() []string {
		ret := []string{}
		filepath.Walk(filepath.Join(global_config_path, "sets"), func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				if vcs_dirs[info.Name()] || strings.HasPrefix(info.Name(), ".")|| strings.HasSuffix(info.Name(), "~"){
					return filepath.SkipDir
				}
			}
			if !info.IsDir(){
				if strings.HasPrefix(info.Name(), ".")|| strings.HasSuffix(info.Name(), "~"){
					ret = append(ret, filepath.Join(path, info.Name()))
				}
			}
			return nil
		})
		dbapi := trees.PortTree().dbapi
		for _, repo := range dbapi.getRepositories("") {
			path := dbapi.getRepositoryPath(repo)
			ret = append(ret, filepath.Join(path, "sets.conf"))
		}

		ret = append(ret, filepath.Join(settings.ValueDict["PORTAGE_CONFIGROOT"], UserConfigPath, "sets.conf"))
		return ret
	}

	return NewSetConfig(_getfiles(), settings, trees)
}
