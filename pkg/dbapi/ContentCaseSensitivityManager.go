package dbapi

import "strings"

type ContentsCaseSensitivityManager struct {
	getcontents           func() map[string][]string
	unmap_key             func(string) string
	contains              func(string) bool
	keys                  func() []string
	_contents_insensitive map[string][]string
	_reverse_key_map      map[string]string
}

func (c *ContentsCaseSensitivityManager) clear_cache() {
	c._contents_insensitive = nil
	c._reverse_key_map = nil
}

func (c *ContentsCaseSensitivityManager) _case_insensitive_init() {
	c._contents_insensitive = map[string][]string{}
	for k, v := range c.getcontents() {
		c._contents_insensitive[strings.ToLower(k)] = v
	}
	c._reverse_key_map = map[string]string{}
	for k := range c.getcontents() {
		c._reverse_key_map[strings.ToLower(k)] = k
	}
}

func (c *ContentsCaseSensitivityManager) _keys_case_insensitive() []string {
	if c._contents_insensitive == nil {
		c._case_insensitive_init()
	}
	ret := []string{}
	for k := range c._contents_insensitive {
		ret = append(ret, k)
	}
	return ret
}

func (c *ContentsCaseSensitivityManager) _contains_case_insensitive(key string) bool {
	if c._contents_insensitive == nil {
		c._case_insensitive_init()
	}
	_, ok := c._contents_insensitive[strings.ToLower(key)]
	return ok
}

func (c *ContentsCaseSensitivityManager) _unmap_key_case_insensitive(key string) string {
	if c._reverse_key_map == nil {
		c._case_insensitive_init()
	}
	return c._reverse_key_map[key]
}

func NewContentsCaseSensitivityManager(db *dblink) *ContentsCaseSensitivityManager {
	c := &ContentsCaseSensitivityManager{}

	c.getcontents = db.getcontents

	c.keys = func() []string {
		ret := []string{}
		for k := range c.getcontents() {
			ret = append(ret, k)
		}
		return ret
	}
	c.contains = func(key string) bool {
		_, ok := c.getcontents()[key]
		return ok
	}
	c.unmap_key = func(key string) string {
		return key
	}
	if db.settings.Features.Features["case-insensitive-fs"] {
		c.unmap_key = c._unmap_key_case_insensitive
		c.contains = c._contains_case_insensitive
		c.keys = c._keys_case_insensitive
	}

	c._contents_insensitive = nil
	c._reverse_key_map = nil
	return c
}
