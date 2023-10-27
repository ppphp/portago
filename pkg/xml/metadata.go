package xml

import (
	"fmt"
)

type _MetadataTreeBuilder struct {
}

func (this *_MetadataTreeBuilder) doctype(name string, pubid string, system string) {
	// Implement doctype() as required to avoid deprecation warnings with
	// Python >=2.7.
}

type _Maintainer struct {
	Email       string
	Name        string
	Description string
	MaintType   string
	Restrict    string
	Status      string
}

func (_this *_Maintainer) __repr__() string {
	return fmt.Sprintf("<%s %r>", "_Maintainer", _this.Email)
}

type _Useflag struct {
	Name        string
	Restrict    string
	Description string
}

func (_this *_Useflag) __repr__() string {
	return fmt.Sprintf("<%s %r>", "_Useflag", _this.Name)
}

type _Upstream struct {
	node        *etree.Element
	maintainers []_Maintainer
	changelogs  []string
	docs        []struct {
		URL string
		Lang string
	}
	bugtrackers []string
	remoteids  []struct {
		Site string
		ID   string
	}
}

func (u *_Upstream) __repr__(v interface{}) string {
	return fmt.Sprintf("<%s %v>", u.__class__, u.__dict__)
}

func (u *_Upstream) upstream_bugtrackers() []string {
	return strings.Join(u.node.findall("bugs-to").filterfunc(func(e *etree.Element) bool {
		return e.text != ""
	}).map(func(e *etree.Element) string {
		return e.text
	}), ",")
}

func (u *_Upstream) upstream_changelogs() []string {
	return strings.Join(u.node.findall("changelog").filterfunc(func(e *etree.Element) bool {
		return e.text != ""
	}).map(func(e *etree.Element) string {
		return e.text
	}), ",")
}

func (u *_Upstream) upstream_documentation() []struct {
	URL string
	Lang string
} {
	result := []struct {
		URL string
		Lang string
	}{}
	for elem := range u.node.findall("doc") {
		if elem.text != "" {
			lang := elem.get("lang")
			result = append(result, struct {
				URL string
				Lang string
			}{URL: elem.text, Lang: lang})
		}
	}
	return result
}

func (u *_Upstream) upstream_maintainers() []_Maintainer {
	return u.node.findall("maintainer").map(func(e *etree.Element) _Maintainer {
		return _Maintainer{e}
	})
}

func (u *_Upstream) upstream_remoteids() []struct {
	Site string
	ID   string
} {
	result := []struct {
		Site string
		ID   string
	}{}
	for elem := range u.node.findall("remote-id") {
		if elem.text != "" {
			result = append(result, struct {
				Site string
				ID   string
			}{Site: elem.text, ID: elem.get("type")})
		}
	}
	return result
}

type MetaDataXML struct {
	metadata_xml_path string
	_xml_tree         *etree.Element
	_herdstree        *etree.Element
	_herds_path       string
	_descriptions     []_Description
	_maintainers      []_Maintainer
	_herds            []_Herd
	_useflags         []_Useflag
	_upstream         *_Upstream
}

func NewMetaDataXML(metadata_xml_path string, herds interface{}) (*MetaDataXML, error) {
	m := &MetaDataXML{
		metadata_xml_path: metadata_xml_path,
	}

	var herds_etree *etree.Element
	var herds_path string

	switch h := herds.(type) {
	case string:
		herds_path = h
	case *etree.Element:
		herds_etree = h
	default:
		return nil, fmt.Errorf("invalid type for herds: %T", herds)
	}

	if m._xml_tree == nil {
		var err error
		m._xml_tree, err = etree.ParseFile(metadata_xml_path)
		if err != nil {
			return nil, err
		}
	}

	if herds_etree == nil {
		var err error
		herds_etree, err = etree.ParseFile(herds_path)
		if err != nil {
			return nil, err
		}
	}

	m._herdstree = herds_etree
	m._herds_path = herds_path

	return m, nil
}

func (m *MetaDataXML) __repr__() string {
	return fmt.Sprintf("<%s %q>", reflect.TypeOf(m).Elem().Name(), m.metadata_xml_path)
}

func (m *MetaDataXML) _get_herd_email(herd string) (string, error) {
	if m._herdstree == nil {
		var err error
		m._herdstree, err = etree.ParseFile(m._herds_path)
		if err != nil {
			return "", err
		}
	}

	for _, elem := range m._herdstree.FindElements("herd") {
		if elem.AttrValue("name", "") == herd {
			return elem.AttrValue("email", ""), nil
		}
	}

	return "", nil
}
class MetaDataXML:

    def __repr__(self):
        return "<%s %r>" % (self.__class__.__name__, self.metadata_xml_path)

    def _get_herd_email(self, herd):
        """Get a herd's email address.

        @type herd: str
        @param herd: herd whose email you want
        @rtype: str or None
        @return: email address or None if herd is not in herds.xml
        @raise IOError: if $PORTDIR/metadata/herds.xml can not be read
        """

        if self._herdstree is None:
            try:
                self._herdstree = etree.parse(
                    _unicode_encode(
                        self._herds_path, encoding=_encodings["fs"], errors="strict"
                    ),
                    parser=etree.XMLParser(target=_MetadataTreeBuilder()),
                )
            except (ImportError, IOError, SyntaxError):
                return None

        # Some special herds are not listed in herds.xml
        if herd in ("no-herd", "maintainer-wanted", "maintainer-needed"):
            return None

        try:
            # Python 2.7 or >=3.2
            iterate = self._herdstree.iter
        except AttributeError:
            iterate = self._herdstree.getiterator

        for node in iterate("herd"):
            if node.findtext("name") == herd:
                return node.findtext("email")

    def herds(self, include_email=False):
        """Return a list of text nodes for <herd>.

        @type include_email: bool
        @keyword include_email: if True, also look up the herd's email
        @rtype: tuple
        @return: if include_email is False, return a list of strings;
                 if include_email is True, return a list of tuples containing:
                                 [('herd1', 'herd1@gentoo.org'), ('no-herd', None);
        """
        if self._herds is None:
            if self._xml_tree is None:
                self._herds = tuple()
            else:
                herds = []
                for elem in self._xml_tree.findall("herd"):
                    text = elem.text
                    if text is None:
                        text = ""
                    if include_email:
                        herd_mail = self._get_herd_email(text)
                        herds.append((text, herd_mail))
                    else:
                        herds.append(text)
                self._herds = tuple(herds)

        return self._herds

    def descriptions(self):
        """Return a list of text nodes for <longdescription>.

        @rtype: list
        @return: package description in string format
        @todo: Support the C{lang} attribute
        """
        if self._descriptions is None:
            if self._xml_tree is None:
                self._descriptions = tuple()
            else:
                self._descriptions = tuple(
                    e.text for e in self._xml_tree.findall("longdescription") if e.text
                )

        return self._descriptions

type MetaDataXML struct {
	metadata_xml_path string
	_xml_tree         *etree.Element
	_herdstree        *etree.Element
	_herds_path       string
	_descriptions     []string
	_maintainers      []_Maintainer
	_herds            []interface{}
	_useflags         []_Useflag
	_upstream         *_Upstream
}

func (m *MetaDataXML) __repr__() string {
	return fmt.Sprintf("<%s %q>", reflect.TypeOf(m).Elem().Name(), m.metadata_xml_path)
}

func (m *MetaDataXML) _get_herd_email(herd string) (string, error) {
	if m._herdstree == nil {
		var err error
		m._herdstree, err = etree.ParseFile(m._herds_path)
		if err != nil {
			return "", err
		}
	}

	// Some special herds are not listed in herds.xml
	if herd == "no-herd" || herd == "maintainer-wanted" || herd == "maintainer-needed" {
		return "", nil
	}

	for _, node := range m._herdstree.FindElements("herd") {
		if node.FindElement("name").Text() == herd {
			return node.FindElement("email").Text(), nil
		}
	}

	return "", nil
}

func (m *MetaDataXML) herds(include_email bool) []interface{} {
	if m._herds == nil {
		if m._xml_tree == nil {
			m._herds = []interface{}{}
		} else {
			herds := []interface{}{}
			for _, elem := range m._xml_tree.FindElements("herd") {
				text := elem.Text()
				if text == "" {
					text = ""
				}
				if include_email {
					herd_mail, _ := m._get_herd_email(text)
					herds = append(herds, []interface{}{text, herd_mail})
				} else {
					herds = append(herds, text)
				}
			}
			m._herds = herds
		}
	}

	return m._herds
}

func (m *MetaDataXML) descriptions() []string {
	if m._descriptions == nil {
		if m._xml_tree == nil {
			m._descriptions = []string{}
		} else {
			descriptions := []string{}
			for _, e := range m._xml_tree.FindElements("longdescription") {
				if e.Text() != "" {
					descriptions = append(descriptions, e.Text())
				}
			}
			m._descriptions = descriptions
		}
	}

	return m._descriptions
}

type MetaDataXML struct {
	_xml_tree     *etree.ElementTree
	_herds_path   string
	_herds        []interface{}
	_herdstree    *etree.Element
	_descriptions []string
	_maintainers  []_Maintainer
	_useflags     []_Useflag
	_upstream     []_Upstream
}

type _Maintainer struct {
	name        string
	email       string
	description string
}

type _Useflag struct {
	name        string
	description string
}

type _Upstream struct {
	maintainers []_Maintainer
	bugtrackers []string
}

func (m *MetaDataXML) maintainers() []_Maintainer {
	if m._maintainers == nil {
		if m._xml_tree == nil {
			m._maintainers = []_Maintainer{}
		} else {
			maintainers := []_Maintainer{}
			for _, elem := range m._xml_tree.FindElements("maintainer") {
				maintainers = append(maintainers, _Maintainer{
					name:        elem.FindElement("name").Text(),
					email:       elem.FindElement("email").Text(),
					description: elem.FindElement("description").Text(),
				})
			}
			m._maintainers = maintainers
		}
	}

	return m._maintainers
}

func (m *MetaDataXML) use() []_Useflag {
	if m._useflags == nil {
		if m._xml_tree == nil {
			m._useflags = []_Useflag{}
		} else {
			useflags := []_Useflag{}
			for _, elem := range m._xml_tree.FindElements("flag") {
				useflags = append(useflags, _Useflag{
					name:        elem.FindElement("name").Text(),
					description: elem.FindElement("description").Text(),
				})
			}
			m._useflags = useflags
		}
	}

	return m._useflags
}

func (m *MetaDataXML) upstream() []_Upstream {
	if m._upstream == nil {
		if m._xml_tree == nil {
			m._upstream = []_Upstream{}
		} else {
			upstreams := []_Upstream{}
			for _, elem := range m._xml_tree.FindElements("upstream") {
				maintainers := []_Maintainer{}
				for _, maintainerElem := range elem.FindElements("maintainer") {
					maintainers = append(maintainers, _Maintainer{
						name:  maintainerElem.FindElement("name").Text(),
						email: maintainerElem.FindElement("email").Text(),
					})
				}

				bugtrackers := []string{}
				for _, bugtrackerElem := range elem.FindElements("bugtracker") {
					bugtrackers = append(bugtrackers, bugtrackerElem.Text())
				}

				upstreams = append(upstreams, _Upstream{
					maintainers: maintainers,
					bugtrackers: bugtrackers,
				})
			}
			m._upstream = upstreams
		}
	}

	return m._upstream
}

func (m *MetaDataXML) formatMaintainerString() string {
	maintainers := []string{}
	for _, maintainer := range m.maintainers() {
		if maintainer.email == "" || strings.TrimSpace(maintainer.email) == "" {
			if maintainer.name != "" && strings.TrimSpace(maintainer.name) != "" {
				maintainers = append(maintainers, maintainer.name)
			}
		} else {
			maintainers = append(maintainers, maintainer.email)
		}
	}

	for _, herd := range m.herds(true) {
		if herd[0] == "no-herd" {
			continue
		}
		if herd[1] == "" || strings.TrimSpace(herd[1]) == "" {
			if herd[0] != "" && strings.TrimSpace(herd[0]) != "" {
				maintainers = append(maintainers, herd[0])
			}
		} else {
			maintainers = append(maintainers, herd[1])
		}
	}

	maintainers = unique(maintainers)

	maintStr := ""
	if len(maintainers) > 0 {
		maintStr = maintainers[0]
		maintainers = maintainers[1:]
	}
	if len(maintainers) > 0 {
		maintStr += " " + strings.Join(maintainers, ",")
	}

	return maintStr
}

func (m *MetaDataXML) formatUpstreamString() string {
	maintainers := []string{}
	for _, upstream := range m.upstream() {
		for _, maintainer := range upstream.maintainers {
			if maintainer.email == "" || strings.TrimSpace(maintainer.email) == "" {
				if maintainer.name != "" && strings.TrimSpace(maintainer.name) != "" {
					maintainers = append(maintainers, maintainer.name)
				}
			} else {
				maintainers = append(maintainers, maintainer.email)
			}
		}

		for _, bugtracker := range upstream.bugtrackers {
			if strings.HasPrefix(bugtracker, "mailto:") {
				bugtracker = bugtracker[7:]
			}
			maintainers = append(maintainers, bugtracker)
		}
	}

	maintainers = unique(maintainers)
	maintStr := strings.Join(maintainers, " ")
	return maintStr
}

func (m *MetaDataXML) herds(include_email bool) []interface{} {
	if m._herds == nil {
		if m._xml_tree == nil {
			m._herds = []interface{}{}
		} else {
			herds := []interface{}{}
			for _, elem := range m._xml_tree.FindElements("herd") {
				text := elem.Text()
				if text == "" {
					text = ""
				}
				if include_email {
					herd_mail, _ := m._get_herd_email(text)
					herds = append(herds, []interface{}{text, herd_mail})
				} else {
					herds = append(herds, text)
				}
			}
			m._herds = herds
		}
	}

	return m._herds
}

func (m *MetaDataXML) descriptions() []string {
	if m._descriptions == nil {
		if m._xml_tree == nil {
			m._descriptions = []string{}
		} else {
			descriptions := []string{}
			for _, e := range m._xml_tree.FindElements("longdescription") {
				if e.Text() != "" {
					descriptions = append(descriptions, e.Text())
				}
			}
			m._descriptions = descriptions
		}
	}

	return m._descriptions
}

func (m *MetaDataXML) _get_herd_email(herd string) (string, error) {
	if m._herdstree == nil {
		var err error
		m._herdstree, err = etree.ParseFile(m._herds_path)
		if err != nil {
			return "", err
		}
	}

	// Some special herds are not listed in herds.xml
	if herd == "no-herd" || herd == "maintainer-wanted" || herd == "maintainer-needed" {
		return "", nil
	}

	for _, node := range m._herdstree.FindElements("herd") {
		if node.FindElement("name").Text() == herd {
			return node.FindElement("email").Text(), nil
		}
	}

	return "", nil
}

func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}


var _lang_pref = map[string]int{
	"": 0,
	"en": 1,
}

func _cmp_lang(a, b *etree.Element) int {
	a_score := _lang_pref[a.AttrValue("lang", "")]
	b_score := _lang_pref[b.AttrValue("lang", "")]
	return a_score - b_score
}

func parse_metadata_use(xml_tree *etree.Element) map[string]map[string]string {
	uselist := make(map[string]map[string]string)

	usetags := xml_tree.FindElements("use")
	if len(usetags) == 0 {
		return uselist
	}

	// Sort by language preference in descending order.
	sort.Slice(usetags, func(i, j int) bool {
		return _cmp_lang(usetags[i], usetags[j]) > 0
	})

	// It's possible to have multiple 'use' elements.
	for _, usetag := range usetags {
		flags := usetag.FindElements("flag")
		if len(flags) == 0 {
			// DTD allows use elements containing no flag elements.
			continue
		}

		for _, flag := range flags {
			pkg_flag := flag.AttrValue("name", "")
			if pkg_flag == "" {
				continue
			}
			flag_restrict := flag.AttrValue("restrict", "")

			// Descriptions may exist for multiple languages, so
			// ignore all except the first description found for a
			// particular value of restrict (see bug 599060).
			if _, ok := uselist[pkg_flag][flag_restrict]; ok {
				continue
			}

			// emulate the Element.itertext() method from python-2.7
			var inner_text []string
			var stack []*etree.Element
			stack = append(stack, flag)
			for len(stack) > 0 {
				obj := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if text := obj.Text(); text != "" {
					inner_text = append(inner_text, text)
				}
				if tail := obj.Tail(); tail != "" {
					stack = append(stack, &etree.Element{Data: tail})
				}
				stack = append(stack, obj.ChildElements()...)
			}

			if _, ok := uselist[pkg_flag]; !ok {
				uselist[pkg_flag] = make(map[string]string)
			}

			// (flag_restrict can be empty)
			uselist[pkg_flag][flag_restrict] = strings.Join(strings.Fields(strings.Join(inner_text, "")), " ")
		}
	}
	return uselist
}
