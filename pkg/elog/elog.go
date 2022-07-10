package elog

import (
	"fmt"
	"github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/exception"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/process"
	"github.com/ppphp/portago/pkg/util/msg"
	"path/filepath"
	"strings"
)

func _preload_elog_modules(settings *config.Config) {
	logsystems := strings.Fields(settings.ValueDict["PORTAGE_ELOG_SYSTEM"])
	for _, s:= range logsystems{
		if strings.Contains(s, ":") {
			s = strings.SplitN(s, ":", 2)[0]
		}
		s = strings.ReplaceAll(s, "-", "_")
	//try:
	//	_load_mod("portage.elog.mod_" + s)
	//	except
	//ImportError:
	//	pass
	}
}

func _merge_logentries(a, b map[string][]struct {
	s  string
	ss []string
}) map[string][]struct{s string;ss []string} {
	rValue := map[string][]struct {
		s  string;
		ss []string
	}{}
	phases := map[string]bool{}
	for k := range a {
		phases[k] = true
	}
	for k := range b {
		phases[k] = true
	}
	for p := range phases {
		merged_msgs := []struct {
			s  string
			ss []string
		}{}
		rValue[p] = merged_msgs
		for _, d := range []map[string][]struct {
			s  string
			ss []string
		}{a, b} {
			msgs := d[p]
			if len(msgs) > 0 {
				merged_msgs = append(merged_msgs, msgs...)
			}
		}
	}
	return rValue
}

func _combine_logentries(logentries map[string][]struct {s  string;ss []string} ) string {
	rValue := []string{}
	for phase := range _const.EBUILD_PHASES {
		if _, ok := logentries[phase]; !ok {
			continue
		}
		previous_type := ""
		for _, v := range logentries[phase] {
			msgtype, msgcontent := v.s, v.ss
			if previous_type != msgtype {
				previous_type = msgtype
				rValue = append(rValue, fmt.Sprintf("%s: %s", msgtype, phase))
			}
			for _, line := range msgcontent {
				rValue = append(rValue, strings.TrimRight(line, "\n"))
			}
		}
	}
	if len(rValue) > 0 {
		rValue = append(rValue, "")
	}
	return strings.Join(rValue, "\n")
}

//_elog_mod_imports = {}
//func _load_mod(name) {
//	global
//	_elog_mod_imports
//	m = _elog_mod_imports.get(name)
//	if m == nil:
//	m = __import__(name)
//	for comp
//	in
//	name.split(".")[1:]:
//	m = getattr(m, comp)
//	_elog_mod_imports[name] = m
//	return m
//}

var _elog_listeners = []func(*config.Config, string, interface{}, interface{}){}

func add_listener(listener func(*config.Config, string, interface{}, interface{})) {
	_elog_listeners = append(_elog_listeners, listener)
}

func remove_listener(listener func(*config.Config, string, interface{}, interface{})) {
	el:= []func(*config.Config, string, interface{}, interface{}){}
	for _, e :=range _elog_listeners {
		for &e != &listener {
			el =append(el, e)
		}
	}
}

var _elog_atexit_handlers = []{}

// nil
func elog_process(cpv string, mysettings *config.Config, phasefilter []string) {

	logsystems1 := strings.Fields(mysettings.ValueDict["PORTAGE_ELOG_SYSTEM"])
	for _, s := range logsystems1 {
		if strings.Contains(s, ":") {
			s= strings.SplitN(s, ":", 1)[0]
			levelss :=  strings.SplitN(s, ":", 1)[1]
			levels := strings.Split(levelss, ",")
		}
		s = strings.ReplaceAll(s, "-", "_")

	//try:
	//	_load_mod("portage.elog.mod_" + s)
	//	except
	//ImportError:
	//	pass
	}
	ebuild_logentries := map[string][]struct {
		s  string
		ss []string
	}{}
	if myutil.Inmss(mysettings.ValueDict, "T") {
		ebuild_logentries = collect_ebuild_messages(filepath.Join(mysettings.ValueDict["T"], "logging"))
	}
	all_logentries := collect_messages(cpv, phasefilter)
	if _, ok := all_logentries[cpv]; ok {
		all_logentries[cpv] = _merge_logentries(all_logentries[cpv], ebuild_logentries)
	} else {
		all_logentries[cpv] = ebuild_logentries
	}

	my_elog_classes := map[string]bool{}
	for _, k := range strings.Fields(mysettings.ValueDict["PORTAGE_ELOG_CLASSES"]) {
		my_elog_classes[k] = true
	}
	logsystems := map[string]map[string]bool{}
	for _, token := range strings.Fields(mysettings.ValueDict["PORTAGE_ELOG_SYSTEM"]) {
		s := token
		levels := []string{}
		if strings.Contains(token, ":") {
			s = strings.SplitN(token, ":", 1)[0]
			level := strings.SplitN(token, ":", 1)[1]
			levels = strings.Split(level, ",")
		}
		levels_set := logsystems[s]
		if levels_set == nil {
			levels_set = map[string]bool{}
			logsystems[s] = levels_set
		}
		for _, k := range levels {
			levels_set[k] = true
		}
	}

	for key := range all_logentries {
		default_logentries := filter_loglevels(all_logentries[key], my_elog_classes)
		if len(default_logentries) == 0 && (!strings.Contains(mysettings.ValueDict["PORTAGE_ELOG_SYSTEM"], ":")) {
			continue
		}

		default_fulllog := _combine_logentries(default_logentries)

		for _, listener := range _elog_listeners {
			listener(mysettings, key, default_logentries, default_fulllog)
		}

		for s, levels := range logsystems {

			mod_logentries := default_logentries
			mod_fulllog := default_fulllog

			if len(levels) > 0 {
				mod_logentries = filter_loglevels(all_logentries[key], levels)
				mod_fulllog = _combine_logentries(mod_logentries)
			}
			if len(mod_logentries) == 0 {
				continue
			}
			s = strings.ReplaceAll(s, "-", "_")
		//try:
		//	AlarmSignal.register(60)
			switch s {
			case "custom":
				custom_process(mysettings, key, mod_logentries, mod_fulllog)
			case "echo":
				echo_process(mysettings, key, mod_logentries, mod_fulllog)
			case "mail":
				mail_process(mysettings, key, mod_logentries, mod_fulllog)
			case "mail_summary":
				mail_summary_process(mysettings, key, mod_logentries, mod_fulllog)
			case "save":
				save_process(mysettings, key, mod_logentries, mod_fulllog)
			case "save_summary":
				save_summary_process(mysettings, key, mod_logentries, mod_fulllog)
			case "syslog":
				syslog_process(mysettings, key, mod_logentries, mod_fulllog)
			}
		//finally:
		//	AlarmSignal.unregister()
			switch s {
			case "echo":

			}
			if hasattr(m, "finalize") &&
				!
					m.finalize
				in
		_elog_atexit_handlers:
			_elog_atexit_handlers = append(_elog_atexit_handlers, m.finalize)
			process.Atexit_register(m.finalize)
			except(ImportError, AttributeError)
			as
		e:
			msg.WriteMsg(_("!!! Error while importing logging modules "
			"while loading \"mod_%s\":\n") % str(s))
			msg.WriteMsg(fmt.Sprintf("%s\n", str(e)), -1, nil)
			except
		AlarmSignal:
			msg.WriteMsg(fmt.Sprintf("Timeout in elog_process for system '%s'\n",s), -1, nil)
			except
			exception.PortageException
			as
		e:
			msg.WriteMsg("%s\n"%str(e), -1, nil)
		}
	}
}
