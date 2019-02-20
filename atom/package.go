package atom

var (
	depKeys                = map[string]bool{"BDEPEND": true, "DEPEND": true, "HDEPEND": true, "PDEPEND": true, "RDEPEND": true}
	buildtimeKeys          = map[string]bool{"BDEPEND": true, "DEPEND": true, "HDEPEND": true}
	runtimeKeys            = map[string]bool{"PDEPEND": true, "RDEPEND": true}
	useConditionalMiscKeys = map[string]bool{"LICENSE": true, "PROPERTIES": true, "RESTRICT": true}

	metadata_keys = []string{
		"BDEPEND", "BUILD_ID", "BUILD_TIME", "CHOST", "COUNTER", "DEFINED_PHASES",
		"DEPEND", "EAPI", "HDEPEND", "INHERITED", "IUSE", "KEYWORDS",
		"LICENSE", "MD5", "PDEPEND", "PROVIDES", "RDEPEND", "repository", "REQUIRED_USE",
		"PROPERTIES", "REQUIRES", "RESTRICT", "SIZE", "SLOT", "USE", "_mtime_"}
)

type Task struct {
	hashKey   string
	hashValue string
}

func (t *Task) eq(task Task) bool {
	return t.hashKey == task.hashKey
}

func (t *Task) ne(task Task) bool {
	return t.hashKey != task.hashKey
}

func (t *Task) hash() string {
	return t.hashValue
}

func (t *Task) len() int {
	return len(t.hashKey)
}

type Package struct {
	built bool
	cpv string
	depth string
	installed string
	onlydeps string
	peration string
	root_config string
	type_name string
	category string
	counter string
	cp string
	cpv_split string
	inherited string
	iuse string
	mtime string
	pf string
	root string
	slot string
	sub_slot string
	slot_atom string
	version string
	_invalid string
	_masks string
	metadata map[string]string
	_provided_cps string
	_raw_metadata string
	_provides string
	_requires string
	_use string
	_validated_atoms string
	_visible string
}

//func (p *Package)eapi()string{
//	return p.metadata["EAPI"]
//}
//
//func (p *Package)buildId()string{
//	return p.cpv.buildId
//}
//
//func (p *Package)buildTime()string{
//	return p.cpv.buildTime
//}
//
//func (p *Package)definedPhases()string{
//	return p.metadata["EAPI"]
//}


