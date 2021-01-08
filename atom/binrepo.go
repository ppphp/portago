package atom

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
)

type BinRepoConfig struct {
	name, name_fallback, sync_uri string
	'fetchcommand',
	'priority',
	'resumecommand',
}

func (b *BinRepoConfig)info_string() string{
	indent := "    "
	repo_msg := []string{}
	if b.name != "" {
		repo_msg=append(repo_msg, b.name)
	} else {
		repo_msg=append(repo_msg, b.name_fallback)
	}
if b.priority is not None{
		repo_msg=append(repo_msg,indent + "priority: " + str(b.priority))
	}
	repo_msg=append(repo_msg,indent + "sync-uri: " + b.sync_uri)
	repo_msg=append(repo_msg,"")
return strings.Join(repo_msg,"\n")
}

func NewBinRepoConfig(opts) *BinRepoConfig {
	b := &BinRepoConfig{}

	for k in self.__slots__:
	setattr(self, k, opts.get(k.replace('_', '-')))
	return b
}


type BinRepoConfigLoader struct {

}//(Mapping):


func (b*BinRepoConfigLoader)_normalize_uri(uri string)string {
	return strings.TrimRight(uri, "/")
}

func (b*BinRepoConfigLoader)_parse(paths, defaults) {
	parser := SafeConfigParser(defaults = defaults)
	recursive_paths = []
for p in paths:
if isinstance(p, str):
recursive_paths.extend(_recursive_file_list(p)) else:
recursive_paths.append(p)

read_configs(parser, recursive_paths)
return parser
}

func (b*BinRepoConfigLoader)__iter__() {
	return iter(b._data)
}

func (b*BinRepoConfigLoader)__contains__( key) {
	return key
	in
	b._data
}

func (b*BinRepoConfigLoader)__getitem__(key) {
	return b._data[key]
}

func (b*BinRepoConfigLoader)__len__() {
	return len(b._data)
}


func NewBinRepoConfigLoader(paths, settings) *BinRepoConfigLoader{

	parser_defaults = {
		"EPREFIX" : settings["EPREFIX"],
			"EROOT" : settings["EROOT"],
			"PORTAGE_CONFIGROOT" : settings["PORTAGE_CONFIGROOT"],
			"ROOT" : settings["ROOT"],
	}

try:
	parser = self._parse(paths, parser_defaults)
	except ConfigParserError as e:
	writemsg(
		_("!!! Error while reading binrepo config file: %s\n") % e,
		noiselevel=-1)
	parser = SafeConfigParser(defaults=parser_defaults)

	repos = []
sync_uris = []
for section_name in parser.sections():
repo_data = dict(parser[section_name].items())
repo_data['name'] = section_name
repo = BinRepoConfig(repo_data)
if repo.sync_uri is None:
writemsg(_("!!! Missing sync-uri setting for binrepo %s\n") % (repo.name,), noiselevel=-1)
continue

sync_uri = self._normalize_uri(repo.sync_uri)
sync_uris.append(sync_uri)
repo.sync_uri = sync_uri
if repo.priority is not None:
try:
repo.priority = int(repo.priority)
except ValueError:
repo.priority = None
repos.append(repo)

sync_uris = set(sync_uris)
current_priority = 0
for sync_uri in reversed(settings.get("PORTAGE_BINHOST", "").split()):
sync_uri = self._normalize_uri(sync_uri)
if sync_uri not in sync_uris:
current_priority += 1
sync_uris.add(sync_uri)
repos.append(BinRepoConfig({
'name-fallback': self._digest_uri(sync_uri),
'name': None,
'priority': current_priority,
'sync-uri': sync_uri,
}))

self._data = OrderedDict((repo.name or repo.name_fallback, repo) for repo in
sorted(repos, key=lambda repo: (repo.priority or 0, repo.name or repo.name_fallback)))

}
func (b*BinRepoConfigLoader) _digest_uri(uri string) string {
	h := md5.New()
	h.Write([]byte(uri))
	return hex.EncodeToString(h.Sum(nil))
}
