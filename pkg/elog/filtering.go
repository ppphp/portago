package elog

import "strings"

func filter_loglevels(logentries map[string][]struct {
	s  string
	ss []string
}, loglevels map[string]bool) map[string][]struct {
	s  string
	ss []string
} {
	rValue := map[string][]struct {
		s  string
		ss []string
	}{}
	for i := range loglevels {
		delete(loglevels, i)
		loglevels[strings.ToUpper(i)] = true
	}
	for phase := range logentries {
		for _, v := range logentries[phase] {
			msgtype, msgcontent := v.s, v.ss
			if loglevels[strings.ToUpper(msgtype)] || loglevels["*"] {
				if _, ok := rValue[phase]; !ok {
					rValue[phase] = []struct {
						s  string
						ss []string
					}{}
				}
				rValue[phase] = append(rValue[phase], struct {
					s  string
					ss []string
				}{msgtype, msgcontent})
			}
		}
	}
	return rValue
}
