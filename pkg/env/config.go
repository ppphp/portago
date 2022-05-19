package env

type configLoaderKlass struct {
	loader interface {
		Load() (map[string][]string, map[string][]string)
	}
}

func (c *configLoaderKlass) load() (map[string][]string, map[string][]string) {
	return c.loader.Load()
}

func NewConfigLoaderKlass(loader interface {
	Load() (map[string][]string, map[string][]string)
}) *configLoaderKlass {
	return &configLoaderKlass{loader: loader}
}

type genericFile struct {
	filename     string
	data, errors map[string][]string
}

func (g *genericFile) load() {
	a := NewKeyListFileLoader(g.filename, nil, nil)
	data, errors := a.Load()
	if len(data) > 0 && len(errors) != 0 {
		g.data, g.errors = data, errors
		return
	}
	b := NewKeyValuePairFileLoader(g.filename, nil, nil)
	data, errors = b.Load()
	if len(data) > 0 && len(errors) != 0 {
		g.data, g.errors = data, errors
		return
	}
	c := NewItemFileLoader(g.filename, nil)
	data, errors = c.Load()
	if len(data) > 0 && len(errors) != 0 {
		g.data, g.errors = data, errors
		return
	}
}

func NewGenericFile(filename string) *genericFile {
	return &genericFile{filename: filename}
}

type packageKeywordsFile struct {
	configLoaderKlass
}

func NewPackageKeywordsFile(filename string) *packageKeywordsFile {
	return &packageKeywordsFile{configLoaderKlass{loader: NewKeyListFileLoader(filename, nil, nil)}}
}

type packageUseFile struct {
	configLoaderKlass
}

func NewPackageUseFile(filename string) *packageUseFile {
	return &packageUseFile{configLoaderKlass{loader: NewItemFileLoader(filename, nil)}}
}

type portageModulesFile struct {
	configLoaderKlass
}

func NewPortageModulesFile(filename string) *portageModulesFile {
	return &portageModulesFile{configLoaderKlass{loader: NewKeyValuePairFileLoader(filename, nil, nil)}}
}
