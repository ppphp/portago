package config

import (
	"fmt"
	_const "github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/util/msg"
	"sort"
	"strings"
)

type featuresSet struct {
	settings *Config
	Features map[string]bool
}

func (f *featuresSet) contains(k string) bool {
	return f.Features[k]
}

func (f *featuresSet) iter() []string {
	r := []string{}
	for k := range f.Features {
		r = append(r, k)
	}
	return r
}

func (f *featuresSet) syncEnvVar() {
	p := f.iter()
	sort.Strings(p)
	f.settings.ValueDict["FEATURES"] = strings.Join(p, " ")
}

func (f *featuresSet) add(k string) {
	f.settings.modifying()
	f.settings.featuresOverrides = append(f.settings.featuresOverrides, k)
	if !f.Features[k] {
		f.Features[k] = true
		f.syncEnvVar()
	}
}

func (f *featuresSet) update(values []string) {
	f.settings.modifying()
	f.settings.featuresOverrides = append(f.settings.featuresOverrides, values...)
	needSync := false
	for _, k := range values {
		if f.Features[k] {
			continue
		}
		f.Features[k] = true
		needSync = true
	}
	if needSync {
		f.syncEnvVar()
	}
}

func (f *featuresSet) differenceUpdate(values []string) {
	f.settings.modifying()
	removeUs := []string{}
	for _, v := range values {
		f.settings.featuresOverrides = append(f.settings.featuresOverrides, "-"+v)
		if f.Features[v] {
			removeUs = append(removeUs, v)
		}
	}
	if len(removeUs) > 0 {
		for _, k := range removeUs {
			delete(f.Features, k)
		}
		f.syncEnvVar()
	}
}

func (f *featuresSet) remove(k string) {
	f.Discard(k)
}

func (f *featuresSet) Discard(k string) {
	f.settings.modifying()
	f.settings.featuresOverrides = append(f.settings.featuresOverrides, "-"+k)
	if f.Features[k] {
		delete(f.Features, k)
	}
	f.syncEnvVar()
}

func (f *featuresSet) validate() {
	if f.Features["unknown-features-warn"] {
		var unknownFeatures []string
		for k := range f.Features {
			if !_const.SUPPORTED_FEATURES[k] {
				unknownFeatures = append(unknownFeatures, k)
			}
		}
		if len(unknownFeatures) > 0 {
			var unknownFeatures2 []string
			for _, u := range unknownFeatures {
				if !f.settings.unknownFeatures[u] {
					unknownFeatures2 = append(unknownFeatures2, u)
				}
			}
			if len(unknownFeatures2) > 0 {
				for _, u := range unknownFeatures2 {
					f.settings.unknownFeatures[u] = true
				}
				msg.WriteMsgLevel(output.Colorize("BAD", fmt.Sprintf("FEATURES variable contains unknown value(s): %s", strings.Join(unknownFeatures2, ", "))+"\n"), 30, -1)
			}
		}
	}
	if f.Features["unknown-features-filter"] {
		var unknownFeatures []string
		for k := range f.Features {
			if !_const.SUPPORTED_FEATURES[k] {
				unknownFeatures = append(unknownFeatures, k)
			}
		}
		if len(unknownFeatures) > 0 {
			f.differenceUpdate(unknownFeatures)
			f.pruneOverrides()
		}
	}
}

func (f *featuresSet) pruneOverrides() {
	overridesSet := map[string]bool{}

	positive := map[string]bool{}
	negative := map[string]bool{}
	for _, u := range f.settings.featuresOverrides {
		overridesSet[u] = true
	}
	for _, x := range f.settings.featuresOverrides {
		if x[:1] == "-" {
			delete(positive, x[1:])
			negative[x[1:]] = true
		} else {
			delete(negative, x)
			positive[x] = true
		}
	}
	f.settings.featuresOverrides = []string{}
	for p := range positive {
		f.settings.featuresOverrides = append(f.settings.featuresOverrides, p)
	}
	for n := range negative {
		f.settings.featuresOverrides = append(f.settings.featuresOverrides, "-"+n)
	}
}

func NewFeaturesSet(settings *Config) *featuresSet {
	return &featuresSet{settings: settings, Features: map[string]bool{}}
}
