package emerge

import (
	"bytes"
	"fmt"
	"github.com/ppphp/portago/pkg/checksum"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/versions"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type BinpkgVerifier struct {
	*CompositeTask

	// slot
	logfile, _digests, _pkg_path string
	pkg                          *versions.PkgStr
}

func (b *BinpkgVerifier) _start() {

	bintree := b.pkg.root_config.trees["bintree"]
	digests := bintree._get_digests(b.pkg)
	if !myutil.InmsT(digests, "size") {
		i := 0
		b.returncode = &i
		b._async_wait()
		return
	}

	digests = checksum.FilterUnaccelaratedHashes(digests)
	hash_filter := checksum.NewHashFilter(
		bintree.settings.ValueDict["PORTAGE_CHECKSUM_FILTER"])
	if !checksum.HashFilterTrasparent(
		bintree.settings.ValueDict["PORTAGE_CHECKSUM_FILTER"]) {
		digests = checksum.ApplyHashFilter(digests, hash_filter)
	}

	b._digests = digests

	st, err := os.Stat(b._pkg_path)
	if err != nil {
		//except OSError as e:
		if err != syscall.ENOENT || err != syscall.ESTALE {
			//raise
		}
		b.scheduler.output(fmt.Sprintf("!!! Fetching Binary failed for '%s'\n", b.pkg.Cpv), b.logfile, b.background, 0, -1)
		i := 1
		b.returncode = &i
		b._async_wait()
		return
	} else {
		size := st.Size()
		if size != digests["size"] {
			b._digest_exception("size", size, digests["size"])
			i := 1
			b.returncode = &i
			b._async_wait()
			return
		}
	}

	ds := []string{}
	for k := range digests {
		if k != "size" {
			ds = append(ds, k)
		}
	}
	b._start_task(NewFileDigester(b._pkg_path, ds, b.background, b.logfile, b.scheduler), b._digester_exit)
}

func (b *BinpkgVerifier) _digester_exit(digester) {

	if b._default_exit(digester) != 0 {
		b.wait()
		return
	}

	for hash_name := range digester.hash_names {
		if digester.digests[hash_name] != b._digests[hash_name] {
			b._digest_exception(hash_name,
				digester.digests[hash_name], b._digests[hash_name])
			i := 1
			b.returncode = &i
			b.wait()
			return
		}
	}

	if b.pkg.root_config.settings.ValueDict["PORTAGE_QUIET"] != "1" {
		b._display_success()
	}

	i := 0
	b.returncode = &i
	b.wait()
}

func (b *BinpkgVerifier) _display_success() {
	stdout_orig := os.Stdout
	stderr_orig := os.Stderr
	global_havecolor := output.HaveColor
	out := &bytes.Buffer{}
	os.Stdout = out
	os.Stderr = out
	if output.HaveColor != 0 {
		if b.background {
			output.HaveColor = 1
		} else {
			output.HaveColor = 0
		}
	}

	path := b._pkg_path
	if strings.HasSuffix(path, ".partial") {
		path = path[:-len(".partial")]
	}
	eout := output.NewEOutput(false)
	eout.Ebegin(fmt.Sprintf("%s %s ;-)", filepath.Base(path),
		strings.Join(myutil.Sorted(b._digests), " ")))
	eout.Eend(0, "")

	os.Stdout = stdout_orig
	os.Stderr = stderr_orig
	output.HaveColor = global_havecolor

	b.scheduler.output(out.String(), b.logfile, b.background, 0, -1)
}

func (b *BinpkgVerifier) _digest_exception(name, value, expected string) {

	head, tail := filepath.Split(b._pkg_path)
	temp_filename := atom._checksum_failure_temp_file(b.pkg.root_config.settings, head, tail)

	b.scheduler.output(fmt.Sprintf(
		"\n!!! Digest verification failed:\n"+
			"!!! %s\n"+
			"!!! Reason: Failed on %s verification\n"+
			"!!! Got: %s\n"+
			"!!! Expected: %s\n"+
			"File renamed to '%s'\n",
		b._pkg_path, name, value, expected, temp_filename),
		b.logfile, b.background, 0, -1)
}

func NewBinpkgVerifier(background bool, logfile string, pkg *versions.PkgStr, scheduler *SchedulerInterface, pkg_path string) *BinpkgVerifier {
	b := &BinpkgVerifier{}
	b.CompositeTask = NewCompositeTask()

	b.background = background
	b.logfile = logfile
	b.pkg = pkg
	b.scheduler = scheduler
	b._pkg_path = pkg_path

	return b
}
