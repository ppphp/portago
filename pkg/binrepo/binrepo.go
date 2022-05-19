package binrepo

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/ppphp/configparser"
	"github.com/ppphp/portago/pkg/ebuild"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/util"
	"strconv"
	"strings"
)

type BinRepoConfig struct {
	// slot
	name, name_fallback, sync_uri string
	priority                      *int
	fetchcommand                  string
	resumecommand                 string
}

func (b *BinRepoConfig) info_string() string {
	indent := "    "
	repo_msg := []string{}
	if b.name != "" {
		repo_msg = append(repo_msg, b.name)
	} else {
		repo_msg = append(repo_msg, b.name_fallback)
	}
	if b.priority != nil {
		repo_msg = append(repo_msg, indent+"priority: "+fmt.Sprint(b.priority))
	}
	repo_msg = append(repo_msg, indent+"sync-uri: "+b.sync_uri)
	repo_msg = append(repo_msg, "")
	return strings.Join(repo_msg, "\n")
}

func NewBinRepoConfig(opts map[string]string) *BinRepoConfig {
	b := &BinRepoConfig{}

	b.name = opts["name"]
	b.name_fallback = opts["name-fallback"]
	b.sync_uri = opts["sync-uri"]

	if n, err := strconv.Atoi(opts["priority"]); err != nil {
		b.priority = &n
	}
	b.fetchcommand = opts["fetchcommand"]
	b.resumecommand = opts["resumecommand"]

	return b
}

type BinRepoConfigLoader struct {
	_data map[string]*BinRepoConfig
} //(Mapping):

func (b *BinRepoConfigLoader) _normalize_uri(uri string) string {
	return strings.TrimRight(uri, "/")
}

func (b *BinRepoConfigLoader) _parse(paths []string, defaults map[string]string) configparser.ConfigParser {
	da := configparser.DefaultArgument
	da.Defaults = defaults
	parser := configparser.NewConfigParser(configparser.DefaultArgument)
	recursive_paths := []string{}
	for _, p := range paths {
		//if isinstance(p, str):
		recursive_paths = append(recursive_paths, util.RecursiveFileList(p)...)
		//else:
		//recursive_paths.append(p)
	}

	util.ReadConfigs(parser, recursive_paths)
	return parser
}

func (b *BinRepoConfigLoader) __iter__() {
	//return iter(b._data)
}

func (b *BinRepoConfigLoader) __contains__(key string) bool {
	_, ok := b._data[key]
	return ok
}

func (b *BinRepoConfigLoader) __getitem__(key string) *BinRepoConfig {
	return b._data[key]
}

func (b *BinRepoConfigLoader) __len__() int {
	return len(b._data)
}

func NewBinRepoConfigLoader(paths []string, settings *ebuild.Config) *BinRepoConfigLoader {
	b := &BinRepoConfigLoader{}

	parser_defaults := map[string]string{
		"EPREFIX":            settings.ValueDict["EPREFIX"],
		"EROOT":              settings.ValueDict["EROOT"],
		"PORTAGE_CONFIGROOT": settings.ValueDict["PORTAGE_CONFIGROOT"],
		"ROOT":               settings.ValueDict["ROOT"],
	}

	//try:
	parser := b._parse(paths, parser_defaults)
	//except ConfigParserError as e:
	//writemsg(
	//	_("!!! Error while reading binrepo config file: %s\n") % e,
	//	noiselevel=-1)
	//parser = SafeConfigParser(defaults=parser_defaults)

	repos := []*BinRepoConfig{}
	sync_uris := []string{}
	for _, section_name := range parser.Sections() {
		repo_data := parser.GetSectionMap()[section_name]
		repo_data["name"] = section_name
		repo := NewBinRepoConfig(repo_data)
		if repo.sync_uri == "" {
			util.WriteMsg(fmt.Sprintf("!!! Missing sync-uri setting for binrepo %s\n", repo.name), -1, nil)
			continue
		}

		sync_uri := b._normalize_uri(repo.sync_uri)
		sync_uris = append(sync_uris, sync_uri)
		repo.sync_uri = sync_uri
		if repo.priority != nil {
			//try:
			//	repo.priority = strconv.Atoi(repo.priority)
			//	except
			//ValueError:
			//	repo.priority = None
			repos = append(repos, repo)
		}
	}

	sync_urisM := map[string]bool{}
	for _, s := range sync_uris {
		sync_urisM[s] = true
	}
	current_priority := 0
	for _, sync_uri := range myutil.Reversed(strings.Fields(settings.ValueDict["PORTAGE_BINHOST"])) {
		sync_uri = b._normalize_uri(sync_uri)
		if !sync_urisM[sync_uri] {
			current_priority += 1
			sync_urisM[sync_uri] = true
			repos = append(repos, NewBinRepoConfig(map[string]string{
				"name-fallback": b._digest_uri(sync_uri),
				"name":          "",
				"priority":      fmt.Sprint(current_priority),
				"sync-uri":      sync_uri,
			}))
		}
	}

	b._data = map[string]*BinRepoConfig{}
	for _, repo := range repos {
		if repo.name != "" {
			b._data[repo.name] = repo
		} else {
			b._data[repo.name_fallback] = repo
		}
	}
	//OrderedDict((repo.name or repo.name_fallback, repo)
	//for repo in sorted(
	//	repos,
	//	key = lambda repo: (repo.priority or 0, repo.name or repo.name_fallback)))

	return b

}

func (b *BinRepoConfigLoader) _digest_uri(uri string) string {
	h := md5.New()
	h.Write([]byte(uri))
	return hex.EncodeToString(h.Sum(nil))
}
