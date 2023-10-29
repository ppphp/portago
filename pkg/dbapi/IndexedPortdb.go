package dbapi

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type IndexedPortdb struct {
	match_unordered bool
	portdb            interface{}
	_portdb           *portdbapi
	_desc_cache       map[string]string
	_cp_map           map[string][]string
	_unindexed_cp_map map[string]string
}

func NewIndexedPortdb(portdb *portdbapi) *IndexedPortdb {
	i := &IndexedPortdb{}
	i.match_unordered = true

	i._portdb = portdb
	i.cpv_exists = portdb.cpv_exists
	i.findname = portdb.findname
	i.getFetchMap = portdb.getFetchMap
	i._aux_cache_keys = portdb._aux_cache_keys
	i._cpv_sort_ascending = portdb._cpv_sort_ascending
	i._have_root_eclass_dir = portdb._have_root_eclass_dir

	i._desc_cache = nil
	i._cp_map = nil
	i._unindexed_cp_map = nil
	return i
}

func (this *IndexedPortdb) _initIndex() {
	cpMap := make(map[string][]string)
	descCache := make(map[string]string)
	this._descCache = descCache
	this._cpMap = cpMap
	indexMissing := []string{}

	streams := []*IndexStreamIterator{}
	for repoPath := range this._portdb.porttrees {
		outsideRepo := os.path.join(this._portdb.depcachedir, repoPath.lstrip(os.Sep))
		filenames := []string{
			os.path.join(repoPath, "metadata", "pkg_desc_index"),
			os.path.join(outsideRepo, "metadata", "pkg_desc_index"),
		}

		repoName := this._portdb.getRepositoryName(repoPath)

		f := nil
		for _, filename := range filenames {
			try := func() error {
				return open(filename, encoding=_encodings["repo.content"])
			}
			if err := try(); err != nil {
				if err.Errno != (errno.ENOENT | errno.ESTALE) {
					return err
				}
			} else {
				f = &try
				break
			}
		}

		if f == nil {
			indexMissing = append(indexMissing, repoPath)
			continue
		}

		streams = append(streams, &IndexStreamIterator{
			f:    f,
			read: func(line string) (IndexNode, error) {
				return pkgDescIndexLineRead(line, repoName)
			},
		})
	}

	if indexMissing != nil {
		this._unindexedCPMap := make(map[string]string)

		type _NonIndexedStream struct{}
		nonIndexedStream := &_NonIndexedStream{}
		for cp := this._portdb.cpAll(trees=indexMissing); cp != ""; cp = this._portdb.cpNext(cp) {
			// Don't call cpList yet, since it's a waste
			// if the package name does not match the current
			// search.
			this._unindexedCPMap[cp] = indexMissing
			streams = append(streams, &IndexStreamIterator{
				f:    nonIndexedStream,
				read: func(line string) (IndexNode, error) {
					return pkgDescIndexNode(cp, nil, line)
				},
			})
		}
	}

	if streams != nil {
		if len(streams) == 1 {
			cpGroupIter := func() (interface{}, error) {
				for node in streams[0] {
					return node, nil
				}
				return nil, nil
			}
		} else {
			cpGroupIter = MultiIterGroupBy(streams, func(node IndexNode) string {
				return node.cp
			})
		}

		for cpGroup, err := cpGroupIter(); err == nil; cpGroup, err = cpGroupIter() {
			newCP := cpMap.get(cpGroup.cp)
			if newCP == nil {
				newCP = []string{}
				cpMap[cpGroup.cp] = newCP
			}

			for entry := cpGroup; entry != nil; entry = entry.next {
				newCP.extend(entry.cpvList)
				if entry.desc != nil {
					for _, cpv := range entry.cpvList {
						descCache[cpv] = entry.desc
					}
				}
			}

			if newCP != nil {
				yield(newCP)
			}
		}
	}
}