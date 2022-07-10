package pcache

import (
	"github.com/ppphp/portago/pkg/util/msg"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type hashPath struct {
	location, eclassDir string
}

func (h *hashPath) mtime() time.Time {
	s, _ := os.Stat(h.location)
	return s.ModTime()
}

func NewHashPath(location string) *hashPath {
	return &hashPath{location: location}
}

type Cache struct {
	eclasses                                           map[string]*hashPath
	eclassLocations                                    map[string]string
	eclassLocationsStr, portTreeRoot, masterEclassRoot string
	portTrees                                          []string
}

func (c *Cache) updateEclasses() {
	c.eclasses = map[string]*hashPath{}
	c.eclassLocations = map[string]string{}
	masterEclasses := map[string]time.Time{}
	eclassLen := len(".eclass")
	for _, y := range c.portTrees {
		x := msg.NormalizePath(path.Join(y, "eclass"))
		eclassFileNames, _ := filepath.Glob(x + "/*")
		for _, y := range eclassFileNames {
			if !strings.HasSuffix(y, ".eclass") {
				continue
			}
			obj := NewHashPath(path.Join(x, y))
			obj.eclassDir = x
			mtime := obj.mtime()
			ys := y[:len(y)-eclassLen]
			if x == c.masterEclassRoot {
				masterEclasses[ys] = mtime
				c.eclasses[ys] = obj
				c.eclassLocations[ys] = x
				continue
			}
			masterMTime, ok := masterEclasses[ys]
			if ok {
				if masterMTime == mtime {
					continue
				}
			}
			c.eclasses[ys] = obj
			c.eclassLocations[ys] = x
		}
	}
}

func (c *Cache) Copy() *Cache {
	d := &Cache{eclasses: map[string]*hashPath{}, eclassLocations: map[string]string{}, portTreeRoot: c.portTreeRoot, portTrees: c.portTrees, masterEclassRoot: c.masterEclassRoot}
	for k, v := range c.eclasses {
		d.eclasses[k] = v
	}
	for k, v := range c.eclassLocations {
		d.eclassLocations[k] = v
	}
	return d
}

func (c *Cache) Append(other *Cache) {
	c.portTrees = append(c.portTrees, other.portTrees...)
	for k, v := range other.eclasses {
		c.eclasses[k] = v
	}
	for k, v := range other.eclassLocations {
		c.eclassLocations[k] = v
	}
	c.eclassLocationsStr = ""
}

func NewCache(portTreeRoot, overlays string) *Cache {
	c := &Cache{}
	if overlays != "" {
		//warnings.warn("overlays parameter of portage.eclass_cache.cache constructor is deprecated and no longer used",
		//	DeprecationWarning, stacklevel=2)
	}
	c.eclasses = map[string]*hashPath{}
	c.eclassLocations = map[string]string{}
	c.eclassLocationsStr = ""
	if portTreeRoot != "" {
		c.portTreeRoot = portTreeRoot
		c.portTrees = []string{msg.NormalizePath(c.portTreeRoot)}
		c.masterEclassRoot = path.Join(c.portTrees[0], "eclass")
	}
	return c
}
