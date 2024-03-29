package emerge

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	ogórek "github.com/kisielk/og-rek"
	"github.com/ppphp/portago/atom"
	"github.com/ppphp/portago/pkg/checksum"
	"github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/data"
	"github.com/ppphp/portago/pkg/dbapi"
	"github.com/ppphp/portago/pkg/dep"
	eapi2 "github.com/ppphp/portago/pkg/eapi"
	ebuild2 "github.com/ppphp/portago/pkg/ebuild"
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/elog"
	"github.com/ppphp/portago/pkg/emerge/structs"
	"github.com/ppphp/portago/pkg/exception"
	"github.com/ppphp/portago/pkg/interfaces"
	"github.com/ppphp/portago/pkg/locks"
	"github.com/ppphp/portago/pkg/manifest"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/portage"
	"github.com/ppphp/portago/pkg/portage/vars"
	"github.com/ppphp/portago/pkg/process"
	"github.com/ppphp/portago/pkg/sets"
	"github.com/ppphp/portago/pkg/util"
	bad2 "github.com/ppphp/portago/pkg/util/bad"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/versions"
	"github.com/ppphp/portago/pkg/xpak"
	"github.com/ppphp/shlex"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/sys/unix"
	"io"
	"io/ioutil"
	"math"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// my interface for python abstraction

// ------------------emerge begins

type DepPriorityInterface interface{
	__int__() int
}

type AsynchronousLock struct {
	*AsynchronousTask
	_use_process_by_default bool
	// slot
	_imp                                                        *locks.LockFileS
	_unlock_future                                              interfaces.IFuture
	path,_force_async,_force_dummy,_force_process,_force_thread string
}

func(a *AsynchronousLock) _start() {

	if ! a._force_async {
		var err error
		a._imp, err = locks.Lockfile(a.path, true, false, "", syscall.O_NONBLOCK)
		if err != nil {
			//except TryAgain:
			//pass
		}else {
			i := 0
			a.returncode = &i
			a._async_wait()
			return
		}
	}

	if a._force_process || (!a._force_thread &&
	(a._use_process_by_default ||threading
	is
	dummy_threading)){
	a._imp = NewLockProcess( a.path, a.scheduler)
	}else{
	a._imp = NewLockThread(a.path,a.scheduler, a._force_dummy)
	}

	a._imp.addExitListener(a._imp_exit)
	a._imp.start()
}

func(a *AsynchronousLock) _imp_exit(imp) {
	a.returncode = imp.returncode
	a._async_wait()
}

func(a *AsynchronousLock) _cancel() {
	if b, ok := a._imp.(*AsynchronousTask); ok {
		b.cancel()
	}
}

func(a *AsynchronousLock) _poll() *int {
	if b, ok := a._imp.(*AsynchronousTask); ok {
		b.poll()
	}
	return a.returncode
}

func(a *AsynchronousLock) async_unlock() interfaces.IFuture {
	if a._imp == nil {
		raise
		AssertionError('not locked')
	}
	if a._unlock_future != nil {
		raise
		AssertionError("already unlocked")
	}

	var unlock_future interfaces.IFuture
	if isinstance(a._imp, (_LockProcess, _LockThread)){
		unlock_future = a._imp.async_unlock()
	}else{
		locks.Unlockfile(a._imp)
		unlock_future = a.scheduler.create_future()
		a.scheduler.call_soon(func(){unlock_future.set_result(nil)})
	}
	a._imp = nil
	a._unlock_future = unlock_future
	return unlock_future
}

func NewAsynchronousLock(path string, scheduler *SchedulerInterface)*AsynchronousLock {
	a :=&AsynchronousLock{}
	a._use_process_by_default = true
	a.AsynchronousTask = NewAsynchronousTask()
	a.path = path
	a.scheduler = scheduler

	return a
}

type _LockThread struct {
	*AbstractPollTask
	path,_force_dummy,_thread,_unlock_future string
	_lock_obj *locks.LockFileS
}

func(l *_LockThread) _start() {
	l._registered = true
	threading_mod := threading
	if l._force_dummy {
		threading_mod = dummy_threading
	}
	l._thread = threading_mod.Thread(target = l._run_lock)
	l._thread.daemon = true
	l._thread.start()
}

func(l *_LockThread) _run_lock() {
	l._lock_obj, _ = locks.Lockfile(l.path, true, false, "", 0)
	l.scheduler.call_soon_threadsafe(l._run_lock_cb)
}

func(l *_LockThread) _run_lock_cb() {
	l._unregister()
	i := 0
	l.returncode = &i
	l._async_wait()
}

func(l *_LockThread) _cancel() {
	//pass
}

func(l *_LockThread) _unlock() {
	if l._lock_obj == nil {
		raise
		AssertionError('not locked')
	}
	if l.returncode == nil {
		raise
		AssertionError('lock not acquired yet')
	}
	if l._unlock_future != nil {
		raise
		AssertionError("already unlocked")
	}
	l._unlock_future = l.scheduler.create_future()
	locks.Unlockfile(l._lock_obj)
	l._lock_obj = nil
}

func(l *_LockThread) async_unlock() {
	l._unlock()
	l.scheduler.call_soon(l._unlock_future.set_result, nil)
	return l._unlock_future
}

func(l *_LockThread) _unregister() {
	l._registered = false

	if l._thread != nil {
		l._thread.join()
		l._thread = nil
	}
}

func NewLockThread(path string, scheduler *SchedulerInterface, force_dummy)*_LockThread {
	l := &_LockThread{}
	l.AbstractPollTask = NewAbstractPollTask()
	l.path=path
	l.scheduler=scheduler
	l._force_dummy = force_dummy
	return l
}

type _LockProcess struct {
	*AbstractPollTask
	//slot
	_proc           *SpawnProcess
	path,_kill_test string
	_acquired bool
	_files          map[string]int
	_unlock_future  interfaces.IFuture
}

func(l *_LockProcess) _start() {
	in2 := make([]int, 2)
	syscall.Pipe(in2)
	in_pr, in_pw :=in2[0],in2[1]
	out2 := make([]int, 2)
	syscall.Pipe(out2)
	out_pr, out_pw := out2[0], out2[1]
	l._files =map[string]int{}
	l._files["pipe_in"] = in_pr
	l._files["pipe_out"] = out_pw

	ar , _ := unix.FcntlInt(in_pr, unix.F_GETFL)|syscall.O_NONBLOCK)
	unix.FcntlInt(in_pr, unix.F_SETFL, ar)

	fcntl.fcntl(in_pr, fcntl.F_SETFL,
		fcntl.fcntl(in_pr, fcntl.F_GETFL)|os.O_NONBLOCK)

	if sys.hexversion < 0x3040000:
try:
	fcntl.FD_CLOEXEC
	except
AttributeError:
	pass
	else:
	fcntl.fcntl(in_pr, fcntl.F_SETFD,
		fcntl.fcntl(in_pr, fcntl.F_GETFD)|fcntl.FD_CLOEXEC)

	l.scheduler.add_reader(in_pr, l._output_handler)
	l._registered = true
	ev := util.ExpandEnv()
	ev["PORTAGE_PYM_PATH"]=portage._pym_path
	l._proc = NewSpawnProcess([]string{portage._python_interpreter,
		filepath.Join(portage._bin_path, "lock-helper.py"), l.path},false,
		ev, map[int]int{0:out_pr, 1:in_pw, 2:syscall.Stderr}, l.scheduler, "")
l._proc.addExitListener(l._proc_exit)
l._proc.start()
syscall.Close(out_pr)
syscall.Close(in_pw)
}

func(l *_LockProcess) _proc_exit(proc) {

	if l._files != nil {
		pipe_out, ok := l._files["pipe_out"]
		delete(l._files, "pipe_out")
		if !ok {
			//except KeyError:
			//pass
		} else {
			syscall.Close(pipe_out)
		}
	}

	if proc.returncode != 0 {
		if !l._acquire {
			if !(l.cancelled || l._kill_test) {
				msg.WriteMsgLevel(fmt.Sprintf("_LockProcess: %s\n",
					fmt.Sprintf("failed to acquire lock on '%s'", l.path, )),
					40, -1)
			}
			l._unregister()
			l.returncode = proc.returncode
			l._async_wait()
			return
		}

		if !l.cancelled && l._unlock_future == nil {
			//raise AssertionError("lock process failed with returncode %s"
			//% (proc.returncode,))
		}
	}

	if l._unlock_future != nil {
		l._unlock_future.set_result(nil)
	}
}

func(l *_LockProcess) _cancel() {
	if l._proc != nil {
		l._proc.cancel()
	}
}

func(l *_LockProcess) _poll() *int {
	if l._proc != nil {
		l._proc.poll()
	}
	return l.returncode
}

func(l *_LockProcess) _output_handler() bool{
	buf := l._read_buf(l._files["pipe_in"])
	if len(buf) > 0 {
		l._acquired = true
		l._unregister()
		i := 0
		l.returncode = &i
		l._async_wait()
	}

	return true
}

func(l *_LockProcess) _unregister() {
	l._registered = false

	if l._files != nil {
		pipe_in, ok := l._files["pipe_in"]
		if !ok {
			//except KeyError:
			//pass
		} else {
			delete(l._files, "pipe_in")
			l.scheduler.remove_reader(pipe_in)
			syscall.Close(pipe_in)
		}
	}
}

func(l *_LockProcess) _unlock() {
	if l._proc == nil {
		//raise AssertionError('not locked')
	}
	if !l._acquired {
		//raise AssertionError('lock not acquired yet')
	}
	if l.returncode != nil && *l.returncode != 0 {
		//raise AssertionError("lock process failed with returncode %s"% (l.returncode,))
	}
	if l._unlock_future != nil {
		//raise AssertionError("already unlocked")
	}
	l._unlock_future = l.scheduler.create_future()
	syscall.Write(l._files["pipe_out"], []byte{0})
	syscall.Close(l._files["pipe_out"])
	l._files = nil
}

func(l *_LockProcess) async_unlock() {
	l._unlock()
	return l._unlock_future
}

func NewLockProcess(path string, scheduler *SchedulerInterface) *_LockProcess {
	l := &_LockProcess{}
	l.AbstractPollTask = NewAbstractPollTask()
	l.path=path
	l.scheduler=scheduler
	return l
}

type Binpkg struct {
	*CompositeTask
	//slot
	logger    *_emerge_log_class
	opts      *_binpkg_opts_class
	pkg_count *_pkg_count_class
	world_atom func()
	_build_prefix, _ebuild_path, _image_dir, _infloc, _pkg_path, _tree, _verify string
	settings                                                                    *config.Config
	pkg                                                                         *versions.PkgStr
	_build_dir                                                                  *EbuildBuildDir
	_bintree                                                                    *dbapi.BinaryTree
	find_blockers,
	ldpath_mtimes,
	prefetcher,
	_fetched_pkg
}

// 0, 0
func (b *Binpkg) _writemsg_level( msg string, level int, noiselevel int) {
	b.scheduler.output(msg, b.settings.ValueDict["PORTAGE_LOG_FILE"], false, level, noiselevel)
}

func (b *Binpkg) _start() {

	pkg := b.pkg
	settings := b.settings
	settings.SetCpv(pkg, nil)
	b._tree = "bintree"
	b._bintree = b.pkg.root_config.trees[b._tree]
	b._verify = !b.opts.pretend

	ss, _ := filepath.EvalSymlinks(settings.ValueDict["PORTAGE_TMPDIR"])
	dir_path := filepath.Join(ss, "portage", pkg.category, pkg.pf)
	b._image_dir = filepath.Join(dir_path, "image")
	b._infloc = filepath.Join(dir_path, "build-info")
	b._ebuild_path = filepath.Join(b._infloc, pkg.pf+".ebuild")
	settings.ValueDict["EBUILD"] = b._ebuild_path
	atom.doebuild_environment(b._ebuild_path, "setup", nil, b.settings, false, nil, b._bintree.dbapi)
	if dir_path != b.settings.ValueDict["PORTAGE_BUILDDIR"] {
		//raise AssertionError("'%s' != '%s'"%
		//	(dir_path, b.Settings.ValueDict["PORTAGE_BUILDDIR"]))
	}
	b._build_dir = NewEbuildBuildDir(b.scheduler, settings)
	settings.configDict["pkg"]["EMERGE_FROM"] = "binary"
	settings.configDict["pkg"]["MERGE_TYPE"] = "binary"

	if eapi2.eapiExportsReplaceVars(settings.ValueDict["EAPI"]) {
		vardb := b.pkg.root_config.trees["vartree"].dbapi
		settings.ValueDict["REPLACING_VERSIONS"] = " ".join(
			set(versions.cpvGetVersion(x, "")
		for x
			in
		vardb.match(b.pkg.slot_atom) +
			vardb.match("="+b.pkg.cpv)))
	}

	prefetcher := b.prefetcher
	if prefetcher == nil{
		//pass
	} else if prefetcher.isAlive() && prefetcher.poll() != nil {
		if !b.background {
			fetch_log := filepath.Join(atom._emerge_log_dir, "emerge-fetch.log")
			msg := []string{
				"Fetching in the background:",
				prefetcher.pkg_path,
				"To view fetch progress, run in another terminal:",
				fmt.Sprintf("tail -f %s", fetch_log),
			}
			out := output.NewEOutput(false)
			for _, l := range msg {
				out.einfo(l)
			}
		}

		b._current_task = prefetcher
		prefetcher.addExitListener(b._prefetch_exit)
		return
	}

	b._prefetch_exit(prefetcher)
}

func (b *Binpkg)_prefetch_exit(prefetcher){
	if b._was_cancelled() {
		b.wait()
		return
	}

	if !(b.opts.pretend || b.opts.fetchonly){
		b._start_task(
			NewAsyncTaskFuture(b._build_dir.async_lock()),
		b._start_fetcher)
	}else {
		b._start_fetcher()
	}
}

// nil
func (b *Binpkg) _start_fetcher( lock_task) {
	if lock_task != nil {
		b._assert_current(lock_task)
		if lock_task.cancelled {
			b._default_final_exit(lock_task)
			return
		}

		lock_task.future.result()
		atom.Prepare_build_dirs(b.settings, true)
		b._build_dir.clean_log()
	}

	pkg := b.pkg
	pkg_count := b.pkg_count
	fetcher := nil

	if b.opts.getbinpkg && b._bintree.isremote(pkg.cpv) {

		fetcher := NewBinpkgFetcher(b.background, b.settings.ValueDict["PORTAGE_LOG_FILE"], b.pkg, b.opts.pretend, b.scheduler)

		msg := fmt.Sprintf(" --- (%s of %s) Fetching Binary (%s::%s)",
			pkg_count.curval, pkg_count.maxval, pkg.cpv,
			fetcher.pkg_path)
		short_msg := fmt.Sprintf("emerge: (%s of %s) %s Fetch",
			pkg_count.curval, pkg_count.maxval, pkg.cpv)
		b.logger.log(msg, short_msg)

		fetcher.addExitListener(b._fetcher_exit)
		b._task_queued(fetcher)
		b.scheduler.fetch.schedule(fetcher)
		return
	}

	b._fetcher_exit(fetcher)
}

func (b *Binpkg) _fetcher_exit( fetcher) {

	if fetcher != nil {
		b._fetched_pkg = fetcher.pkg_path
		if b._default_exit(fetcher) != 0 {
			b._async_unlock_builddir(b.returncode)
			return
		}
	}

	if b.opts.pretend {
		b._current_task = nil
		i:=0
		b.returncode = &i
		b.wait()
		return
	}

	var verifier *BinpkgVerifier
	if b._verify {
		path := ""
		if b._fetched_pkg {
			path = b._fetched_pkg
		} else {
			path = b.pkg.root_config.trees["bintree"].getname(
				b.pkg.cpv)
		}
		logfile := b.settings.ValueDict["PORTAGE_LOG_FILE"]
		verifier = NewBinpkgVerifier( b.background, logfile,b.pkg,  b.scheduler, path)
		b._start_task(verifier, b._verifier_exit)
		return
	}

	b._verifier_exit(verifier)
}

func (b *Binpkg) _verifier_exit(verifier func(*int)) {
	if verifier != nil && b._default_exit(verifier) != 0 {
		b._async_unlock_builddir(b.returncode)
		return
	}

	logger := b.logger
	pkg := b.pkg
	pkg_count := b.pkg_count

	pkg_path := ""
	if b._fetched_pkg {
		pkg_path = b._bintree.getname(b._bintree.inject(pkg.cpv, b._fetched_pkg), false)
	} else {
		pkg_path = b.pkg.root_config.trees["bintree"].getname(
			b.pkg.cpv)
	}

	if pkg_path != "" {
		b.settings.ValueDict["PORTAGE_BINPKG_FILE"] = pkg_path
	}
	b._pkg_path = pkg_path

	logfile := b.settings.ValueDict["PORTAGE_LOG_FILE"]
	st, err := os.Stat(logfile)
	if err == nil && !st.IsDir() {
		if err := syscall.Unlink(logfile); err != nil {
			//except OSError:
			//pass
		}
	}

	if b.opts.fetchonly != "" {
		b._current_task = nil
		i := 0
		b.returncode = &i
		b.wait()
		return
	}

	msg := fmt.Sprintf(" === (%s of %s) Merging Binary (%s::%s)",
		pkg_count.curval, pkg_count.maxval, pkg.cpv, pkg_path)
	short_msg := fmt.Sprintf("emerge: (%s of %s) %s Merge Binary",
		pkg_count.curval, pkg_count.maxval, pkg.cpv)
	logger.log(msg, short_msg)

	phase := "clean"
	settings := b.settings
	ebuild_phase := NewEbuildPhase(nil, b.background,
		phase, b.scheduler, settings, nil)

	b._start_task(ebuild_phase, b._clean_exit)
}

func (b *Binpkg) _clean_exit( clean_phase) {
	if b._default_exit(clean_phase) != 0 {
		b._async_unlock_builddir(b.returncode)
		return
	}

	b._start_task(
		NewAsyncTaskFuture(b._unpack_metadata()),
	b._unpack_metadata_exit)
}

@coroutine
func (b *Binpkg) _unpack_metadata() interfaces.IFuture {

	dir_path := b.settings.ValueDict["PORTAGE_BUILDDIR"]

	infloc := b._infloc
	pkg := b.pkg
	pkg_path := b._pkg_path

	dir_mode := os.FileMode(0755)
	for _, mydir := range []string{dir_path, b._image_dir, infloc} {
		util.EnsureDirs(mydir, uint32(*data.portage_uid), *data.portage_gid, dir_mode, -1, nil, true)
	}

	atom.Prepare_build_dirs(b.settings, true)
	b._writemsg_level(">>> Extracting info\n", 0, 0)

	yield
	b._bintree.dbapi.unpack_metadata(b.settings, infloc)
	check_missing_metadata := []string{"CATEGORY", "PF"}
	for k, versions.v
		in
	zip(check_missing_metadata,
		b._bintree.dbapi.aux_get(b.pkg.cpv, check_missing_metadata)) {
		if versions.v {
			continue
		} else if k == "CATEGORY" {
			versions.v = pkg.category
		} else if k == "PF" {
			versions.v = pkg.pf
		} else {
			continue
		}

		f, _ := os.OpenFile(filepath.Join(infloc, k), os.O_RDWR|os.O_CREATE, 0644)
		f.Write(versions.v)
		f.Write([]byte("\n"))
		f.Close()
	}

	if pkg_path != "" {
		md5sum := b._bintree.dbapi.aux_get(b.pkg.cpv, map[string]string{"MD5": ""})[0]
		if len(md5sum) == 0 {
			md5sum = string(checksum.performMd5(pkg_path, false))
		}
		f, _ := os.OpenFile(filepath.Join(infloc, "BINPKGMD5"), os.O_RDWR|os.O_CREATE, 0644)
		f.Write([]byte(md5sum))
		f.Write([]byte("\n"))
		f.Close()
	}

	env_extractor := NewBinpkgEnvExtractor(b.background,
		b.scheduler, b.settings)
	env_extractor.start()
	yield
	env_extractor.async_wait()
	if env_extractor.returncode != nil && *env_extractor.returncode != 0 {
		raise
		portage.exception.PortageException("failed to extract environment for {}".format(b.pkg.cpv))
	}
}

func (b *Binpkg) _unpack_metadata_exit( unpack_metadata) {
	if b._default_exit(unpack_metadata) != 0 {
		unpack_metadata.future.result()
		b._async_unlock_builddir(b.returncode)
		return
	}

	setup_phase := NewEbuildPhase(nil,  b.background, "setup",b.scheduler, b.settings, nil)

	setup_phase.addExitListener(b._setup_exit)
	b._task_queued(setup_phase)
	b.scheduler.scheduleSetup(setup_phase)
}

func (b *Binpkg) _setup_exit( setup_phase *SpawnProcess) {
	if b._default_exit(setup_phase) != 0 {
		b._async_unlock_builddir(b.returncode)
		return
	}

	b._writemsg_level(fmt.Sprintf(">>> Extracting %s\n" , b.pkg.cpv), 0, 0)
	b._start_task(
		NewAsyncTaskFuture(b._bintree.dbapi.unpack_contents(
		b.settings, b._image_dir)),
	b._unpack_contents_exit)
}

func (b *Binpkg) _unpack_contents_exit( unpack_contents) {
	if b._default_exit(unpack_contents) != 0 {
		unpack_contents.future.result()
		b._writemsg_level(fmt.Sprintf("!!! Error Extracting '%s'\n",
			b._pkg_path), -1, 40)
		b._async_unlock_builddir(b.returncode)
		return
	}

	f, err := ioutil.ReadFile(filepath.Join(b._infloc, "EPREFIX"))
	if err != nil {
		//except IOError:
		b._build_prefix = ""
	} else {
		b._build_prefix = strings.TrimRight(string(f), "\n")
	}

	if b._build_prefix == b.settings.ValueDict["EPREFIX"] {
		util.EnsureDirs(b.settings.ValueDict["ED"], -1, -1, -1, -1, nil, true)
		b._current_task = nil
		i := 0
		b.returncode = &i
		b.wait()
		return
	}

	env := b.settings.environ()
	env["PYTHONPATH"] = b.settings.ValueDict["PORTAGE_PYTHONPATH"]
	chpathtool := NewSpawnProcess(
		[]string{"python", // portage._python_interpreter,
			filepath.Join(b.settings.ValueDict["PORTAGE_BIN_PATH"], "chpathtool.py"),
			b.settings.ValueDict["D"], b._build_prefix, b.settings.ValueDict["EPREFIX"]},
		b.background, env, nil, b.scheduler, b.settings.ValueDict["PORTAGE_LOG_FILE"])
	b._writemsg_level(fmt.Sprintf(">>> Adjusting Prefix to %s\n", b.settings.ValueDict["EPREFIX"]), 0, 0)
	b._start_task(chpathtool, b._chpathtool_exit)
}

func (b *Binpkg) _chpathtool_exit( chpathtool) {
	if i := b._final_exit(chpathtool); i != nil && *i != 0 {
		b._writemsg_level(fmt.Sprintf("!!! Error Adjusting Prefix to %s\n",
			b.settings.ValueDict["EPREFIX"], ),
			-1, 40)
		b._async_unlock_builddir(b.returncode)
		return
	}

	ioutil.WriteFile(filepath.Join(b._infloc, "EPREFIX"), []byte(b.settings.ValueDict["EPREFIX"]+"\n"), 0644)

	image_tmp_dir := filepath.Join(
		b.settings.ValueDict["PORTAGE_BUILDDIR"], "image_tmp")
	build_d := strings.TrimLeft(filepath.Join(b.settings.ValueDict["D"],
		strings.TrimLeft(b._build_prefix, string(os.PathSeparator))), string(os.PathSeparator))
	if myutil.pathIsDir(build_d) {
		os.RemoveAll(b._image_dir)
		util.EnsureDirs(b.settings.ValueDict["ED"], -1, -1, -1, -1, nil, true)
	} else {
		os.Rename(build_d, image_tmp_dir)
		if build_d != b._image_dir {
			os.RemoveAll(b._image_dir)
		}
		util.EnsureDirs(strings.TrimRight(filepath.Dir(b.settings.ValueDict["ED"]), string(os.PathSeparator)), -1, -1, -1, -1, nil, true)
		os.Rename(image_tmp_dir, b.settings.ValueDict["ED"])
	}

	b.wait()
}

// nil
func (b *Binpkg) _async_unlock_builddir(returncode *int) {
	if b.opts.pretend != "" || b.opts.fetchonly != "" {
		if returncode != nil {
			b.returncode = returncode
			b._async_wait()
		}
		return
	}
	if returncode != nil {
		b.returncode = nil
	}
	elog.elog_process(b.pkg.cpv.string, b.settings, nil)
	b._start_task(
		NewAsyncTaskFuture(b._build_dir.async_unlock()),
	func(unlock_task) {
		return b._unlock_builddir_exit(unlock_task, returncode)
	})
}

// nil
func (b *Binpkg) _unlock_builddir_exit(unlock_task, returncode *int) {
	b._assert_current(unlock_task)
	if unlock_task.cancelled && returncode!= nil{
		b._default_final_exit(unlock_task)
		return
	}

	unlock_task.future.cancelled() || unlock_task.future.result()
	if returncode != nil {
		b.returncode = returncode
		b._async_wait()
	}
}

func (b *Binpkg) create_install_task() *EbuildMerge {
	task := NewEbuildMerge(b._install_exit, b.find_blockers,
		b.ldpath_mtimes, b.logger, b.pkg, b.pkg_count,
		b._pkg_path, b.scheduler, b.settings, b._tree, b.world_atom)
	return task
}

func (b *Binpkg) _install_exit(task) {
	delete(b.settings.ValueDict, "PORTAGE_BINPKG_FILE")
	if task.returncode == 0 && !b.settings.Features.Features["binpkg-logs"] && b.settings.ValueDict["PORTAGE_LOG_FILE"]!= "" {
		if err := syscall.Unlink(b.settings.ValueDict["PORTAGE_LOG_FILE"]); err != nil {
			//except OSError:
			//pass
		}
	}
	b._async_unlock_builddir(nil)
	var result interfaces.IFuture
	if b._current_task == nil {
		result = b.scheduler.create_future()
		b.scheduler.call_soon(func(){result.set_result(0)})
	}else {
		result = b._current_task.async_wait()
	}
	return result
}

func NewBinpkg(background bool, find_blockers , ldpath_mtimes, logger*_emerge_log_class,
	opts *_binpkg_opts_class, pkg *versions.PkgStr, pkg_count*_pkg_count_class, prefetcher ,
	settings *config.Config, scheduler *SchedulerInterface,
	world_atom func())*Binpkg {
	b := &Binpkg{}
	b.CompositeTask = NewCompositeTask()
	b.background = background
	b.find_blockers = find_blockers
	b.ldpath_mtimes = ldpath_mtimes
	b.logger = logger
	b.opts = opts
	b.pkg = pkg
	b.pkg_count = pkg_count
	b.prefetcher = prefetcher
	b.settings = settings
	b.scheduler = scheduler
	b.world_atom = world_atom
	return b
}

type BinpkgEnvExtractor struct {
	*CompositeTask
	settings *config.Config
}

func(b *BinpkgEnvExtractor) saved_env_exists() bool {
	return myutil.PathExists(b._get_saved_env_path())
}

func(b *BinpkgEnvExtractor) dest_env_exists() bool {
	return myutil.PathExists(b._get_dest_env_path())
}

func(b *BinpkgEnvExtractor) _get_saved_env_path() string {
	return filepath.Join(filepath.Dir(b.settings.ValueDict["EBUILD"]),
		"environment.bz2")
}

func(b *BinpkgEnvExtractor) _get_dest_env_path() string {
	return filepath.Join(b.settings.ValueDict["T"], "environment")
}

func(b *BinpkgEnvExtractor) _start() {
	saved_env_path := b._get_saved_env_path()
	dest_env_path := b._get_dest_env_path()
	shell_cmd := fmt.Sprintf("${PORTAGE_BUNZIP2_COMMAND:-${PORTAGE_BZIP2_COMMAND} -d} -c -- %s > %s" ,
		vars.ShellQuote(saved_env_path),
		vars.ShellQuote(dest_env_path))
	extractor_proc := NewSpawnProcess([]string{_const.BashBinary, "-c", shell_cmd}, b.background, b.settings.environ(), nil, b.scheduler, b.settings.ValueDict["PORTAGE_LOG_FILE"])

	b._start_task(extractor_proc, b._extractor_exit)
}

func(b *BinpkgEnvExtractor) _remove_dest_env() {
	if err := syscall.Unlink(b._get_dest_env_path()); err != nil {
		//except OSError as e:
		if err != syscall.ENOENT {
			//raise
		}
	}
}

func(b *BinpkgEnvExtractor) _extractor_exit( extractor_proc *SpawnProcess) {

	if b._default_exit(extractor_proc) != 0 {
		b._remove_dest_env()
		b.wait()
		return
	}

	f, _ := os.OpenFile(b._get_dest_env_path()+".raw", os.O_RDWR, 0644)
	f.Close()

	b._current_task = nil
	i := 0
	b.returncode = &i
	b.wait()
}

func NewBinpkgEnvExtractor(background bool, scheduler *SchedulerInterface, settings *config.Config)*BinpkgEnvExtractor {
	b :=&BinpkgEnvExtractor{}
	b.CompositeTask = NewCompositeTask()
	b.background = background
	b.scheduler = scheduler
	b.settings = settings
	return b
}

type BinpkgExtractorAsync struct {
	*SpawnProcess
	_shell_binary string

	// slot
	features  map[string]bool
	pkg       *versions.PkgStr
	pkg_path  string
	image_dir string
}

func(b *BinpkgExtractorAsync) _start() {
	tar_options := ""
	if b.features["xattr"] {
		pp := &bytes.Buffer{}
		cmd := exec.Command("tar", "--help")
		cmd.Stderr = pp
		cmd.Stdout = pp
		cmd.Run()
		output := pp.String()
		if strings.Contains(output, "--xattrs") {
			tar_options2 := []string{"--xattrs", "--xattrs-include='*'"}
			ss, _ := shlex.Split(strings.NewReader(b.env["PORTAGE_XATTR_EXCLUDE"]), false, true)

			for _, x := range ss {
				tar_options2 = append(tar_options2, vars.ShellQuote(fmt.Sprintf("--xattrs-exclude=%s", x)))
			}
			tar_options = strings.Join(tar_options2, " ")
		}
	}
	decomp := util._compressors[util.compression_probe(b.pkg_path)]
	decomp_cmd := ""
	if decomp != nil {
		decomp_cmd = decomp["decompress"]
	} else if tarfile.is_tarfile(b.pkg_path) {
		decomp_cmd = "cat"
		decomp = map[string]string{
			"compress": "cat",
			"package":  "sys-apps/coreutils",
		}
	} else {
		decomp_cmd = ""
	}
	if decomp_cmd == "" {
		b.scheduler.output(fmt.Sprintf("!!! %s\n",
			fmt.Sprintf("File compression header unrecognized: %s",
				b.pkg_path)), b.logfile,
			b.background, 40, 0)
		i := 1
		b.returncode = &i
		b._async_wait()
		return
	}

	dbs, _ := shlex.Split(strings.NewReader(util.VarExpand(decomp_cmd, b.env, nil)), false, true)
	decompression_binary := ""
	if len(dbs) > 0 {
		decompression_binary = dbs[0]
	}

	if process.FindBinary(decompression_binary) == "" {
		if decomp["decompress_alt"] != "" {
			decomp_cmd = decomp["decompress_alt"]
		}
		dbs, _ := shlex.Split(strings.NewReader(util.VarExpand(decomp_cmd, b.env, nil)), false, true)
		decompression_binary = ""
		if len(dbs) > 0 {
			decompression_binary = dbs[0]
		}

		if process.FindBinary(decompression_binary) == "" {
			missing_package := decomp["package"]
			b.scheduler.output(fmt.Sprintf("!!! %s\n",
				fmt.Sprintf("File compression unsupported %s.\n Command was: %s.\n Maybe missing package: %s",
					b.pkg_path, util.VarExpand(decomp_cmd, b.env, nil), missing_package)), b.logfile,
				b.background, 40, -1)
			i := 1
			b.returncode = &i
			b._async_wait()
			return
		}
	}

	pkg_xpak := xpak.NewTbz2(b.pkg_path)
	pkg_xpak.scan()

	b.args = []string{b._shell_binary, "-c",
		fmt.Sprintf("cmd0=(head -c %d -- %s) cmd1=(%s) cmd2=(tar -xp %s -C %s -f -); "+
			`"${cmd0[@]}" | "${cmd1[@]}" | "${cmd2[@]}"; `+
			"p=(${PIPESTATUS[@]}) ; for i in {0..2}; do "+
			"if [[ ${p[$i]} != 0 && ${p[$i]} != %d ]] ; then "+
			"echo command $(eval \"echo \\\"'\\${cmd$i[*]}'\\\"\") "+
			"failed with status ${p[$i]} ; exit ${p[$i]} ; fi ; done; "+
			"if [ ${p[$i]} != 0 ] ; then "+
			"echo command $(eval \"echo \\\"'\\${cmd$i[*]}'\\\"\") "+
			"failed with status ${p[$i]} ; exit ${p[$i]} ; fi ; "+
			"exit 0 ;",
			int(pkg_xpak.filestat.Size())-pkg_xpak.xpaksize,
			vars.ShellQuote(b.pkg_path),
			decomp_cmd,
			tar_options,
			vars.ShellQuote(b.image_dir),
			128+int(unix.SIGPIPE))}

	b.SpawnProcess._start()
}

func NewBinpkgExtractorAsync(background bool, env map[string]string, features map[string]bool, image_dir string, pkg *versions.PkgStr, pkg_path, logfile string, scheduler *SchedulerInterface) *BinpkgExtractorAsync {
	b:= &BinpkgExtractorAsync{}
	b._shell_binary= _const.BashBinary
	b.SpawnProcess= NewSpawnProcess()

	b.background=background
	b.env=env
	b.features=features
	b.image_dir = image_dir
	b.pkg=pkg
	b.pkg_path=pkg_path
	b.logfile=logfile
	b.scheduler=scheduler

	return b
}


type BinpkgFetcher struct {
	*CompositeTask

	// slot
	pkg *versions.PkgStr
	pretend,logfile,pkg_path string
}

func (b *BinpkgFetcher) _start() {
	fetcher := NewBinpkgFetcherProcess(b.background,
		b.logfile, b.pkg, b.pkg_path,
		b.pretend, b.scheduler)

	if not b.pretend {
		util.EnsureDirs(filepath.Dir(b.pkg_path),-1,-1,-1,-1,nil,true)
		if "distlocks" in
		b.pkg.root_config.settings.features
		{
			b._start_task(
				NewAsyncTaskFuture(fetcher.async_lock()),
			functools.partial(b._start_locked, fetcher))
			return
		}
	}

	b._start_task(fetcher, b._fetcher_exit)
}

func (b *BinpkgFetcher) _start_locked(fetcher, lock_task) {
	b._assert_current(lock_task)
	if lock_task.cancelled {
		b._default_final_exit(lock_task)
		return
	}

	lock_task.future.result()
	b._start_task(fetcher, b._fetcher_exit)
}

func (b *BinpkgFetcher) _fetcher_exit(fetcher) {
	b._assert_current(fetcher)
	if not b.pretend
	and
	fetcher.returncode == 0{
		fetcher.sync_timestamp()
	}
	if fetcher.locked {
		b._start_task(
			NewAsyncTaskFuture(fetcher.async_unlock()),
		functools.partial(b._fetcher_exit_unlocked, fetcher))
	}else {
		b._fetcher_exit_unlocked(fetcher)
	}
}

// nil
func (b *BinpkgFetcher) _fetcher_exit_unlocked(fetcher, unlock_task=None) {
	if unlock_task != nil {
		b._assert_current(unlock_task)
		if unlock_task.cancelled {
			b._default_final_exit(unlock_task)
			return
		}
	}

	unlock_task.future.result()

	b._current_task = None
	b.returncode = fetcher.returncode
	b._async_wait()
}

func NewBinpkgFetcher(background bool, logfile string, pkg *versions.PkgStr, pretend interface{}, scheduler *SchedulerInterface, **kwargs)*BinpkgFetcher {
	b :=&BinpkgFetcher{}
	b.CompositeTask= NewCompositeTask()
	b.background = background
	b.logfile=logfile
	b.pkg=pkg
	b.pretend = pretend
	b.scheduler=scheduler

	pkg := b.pkg
	b.pkg_path = pkg.root_config.trees["bintree"].getname(
		pkg.cpv) + ".partial"

	return b
}

type _BinpkgFetcherProcess struct {
	*SpawnProcess

	// slot
	locked bool
	pkg,pretend,pkg_path string
	_lock_obj *AsynchronousLock
}

func (b *_BinpkgFetcherProcess) _start() {
	pkg := b.pkg
	pretend := b.pretend
	bintree := pkg.root_config.trees["bintree"]
	settings := bintree.settings
	pkg_path := b.pkg_path

	exists := myutil.PathExists(pkg_path)
	resume := exists && filepath.Base(pkg_path)
	in
	bintree.invalids
	if !(pretend || resume) {
		if err := syscall.Unlink(pkg_path); err != nil {
			//except OSError:
			//pass
		}
	}

	uri := strings.TrimRight(settings.ValueDict["PORTAGE_BINHOST"], "/") + "/" + pkg.pf + ".tbz2"
	if bintree._remote_has_index {
		instance_key := bintree.dbapi._instance_key(pkg.cpv)
		rel_uri := bintree._remotepkgs[instance_key].get("PATH")
		if rel_uri == "" {
			rel_uri = pkg.cpv + ".tbz2"
		}
		remote_base_uri := bintree._remotepkgs[
			instance_key]["BASE_URI"]
		uri = strings.TrimRight(remote_base_uri, "/") + "/" + strings.TrimLeft(rel_uri, "/")
	}

	if pretend {
		msg.WriteMsgStdout(fmt.Sprintf("\n%s\n", uri), -1)
		i := 0
		b.returncode = &i
		b._async_wait()
		return
	}

	u, _ := url.Parse(uri)
	protocol := u.Scheme
	fcmd_prefix := "FETCHCOMMAND"
	if resume {
		fcmd_prefix = "RESUMECOMMAND"
	}
	fcmd := settings.ValueDict[fcmd_prefix+"_"+strings.ToUpper(protocol)]
	if fcmd == "" {
		fcmd = settings.ValueDict[fcmd_prefix]
	}

	fcmd_vars := map[string]string{
		"DISTDIR": filepath.Dir(pkg_path),
		"URI":     uri,
		"FILE":    filepath.Base(pkg_path),
	}

	v, ok := settings.ValueDict["PORTAGE_SSH_OPTS"]
	if ok {
		fcmd_vars["PORTAGE_SSH_OPTS"] = v
	}

	fetch_env := dict(settings.items())
	fetch_args := []string{}
	ss, _ := shlex.Split(strings.NewReader(fcmd), false, true)
	for _, x := range ss {
		fetch_args = append(fetch_args, util.VarExpand(x, fcmd_vars, nil))
	}

	if b.fd_pipes == nil {
		b.fd_pipes =map[int]int{}
	}
	fd_pipes := b.fd_pipes

	if _, ok := fd_pipes[0]; !ok {
		fd_pipes[0] = int(atom.getStdin().Fd())
	}
	if _, ok := fd_pipes[0]; !ok {
		fd_pipes[0] = int(os.Stdout.Fd())
	}
	if _, ok := fd_pipes[0]; !ok {
		fd_pipes[0] = int(os.Stdout.Fd())
	}

	b.args = fetch_args
	b.env = fetch_env
	if settings.selinux_enabled() {
		b._selinux_type = settings["PORTAGE_FETCH_T"]
	}
	b.SpawnProcess._start()
}

func (b *_BinpkgFetcherProcess) _pipe( fd_pipes map[int]int) []int {
	if b.background || !terminal.IsTerminal(syscall.Stdout){
		return os.pipe()
	}
	stdout_pipe = None
	if ! b.background {
		stdout_pipe = fd_pipes[1]
	}
	got_pty, master_fd, slave_fd =
		_create_pty_or_pipe(copy_term_size = stdout_pipe)
	return (master_fd, slave_fd)
}

func (b *_BinpkgFetcherProcess) sync_timestamp() {
	bintree := b.pkg.root_config.trees["bintree"]
	if bintree._remote_has_index {
		remote_mtime := bintree._remotepkgs[
			bintree.dbapi._instance_key(
				b.pkg.cpv)].get("_mtime_")
		if remote_mtime != nil {
			remote_mtimeI, err := strconv.Atoi(remote_mtime)
			if err == nil {
				st, err := os.Stat(b.pkg_path)
				if err == nil {
					local_mtime := st.ModTime().Unix()
					if remote_mtimeI != int(local_mtime) {
						err := syscall.Utime(b.pkg_path, &syscall.Utimbuf{Actime: remote_mtime, Modtime: remote_mtime})
						if err != nil {
						}
					}
				}
			}
		}
	}
}

func (b *_BinpkgFetcherProcess) async_lock() interfaces.IFuture {
	if b._lock_obj != nil{
		//raise b.AlreadyLocked((b._lock_obj, ))
	}

	result := b.scheduler.create_future()

	acquired_lock := func(async_lock) {
		if async_lock.wait() == 0 {
			b.locked = true
			result.set_result(nil)
		} else {
			result.set_exception(AssertionError(
				"AsynchronousLock failed with returncode %s"
			% (async_lock.returncode,)))
		}
	}

	b._lock_obj = NewAsynchronousLock( b.pkg_path, b.scheduler)
	b._lock_obj.addExitListener(acquired_lock)
	b._lock_obj.start()
	return result
}

type AlreadyLocked struct {
	*exception.PortageException
}

func (b *_BinpkgFetcherProcess) async_unlock() interfaces.IFuture {
	if b._lock_obj == nil{
		//raise AssertionError('already unlocked')
	}
	result := b._lock_obj.async_unlock()
	b._lock_obj = nil
	b.locked = false
	return result
}

func NewBinpkgFetcherProcess(background bool,
	logfile string, pkg *versions.PkgStr, pkg_path string,
	pretend interface{}, scheduler *SchedulerInterface)*_BinpkgFetcherProcess {
	b := &_BinpkgFetcherProcess{}
	b.SpawnProcess = NewSpawnProcess(nil, background, nil, nil, scheduler,
		logfile)

	b.background = background
	b.logfile = logfile
	b.pkg = pkg
	b.pkg_path = pkg_path
	b.pretend = pretend
	b.scheduler = scheduler

	return b
}

type BinpkgPrefetcher struct {
	*CompositeTask

	// slot
	pkg *versions.PkgStr
	pkg_path string
	_bintree *dbapi.BinaryTree
}

func (b *BinpkgPrefetcher)_start() {
	b._bintree = b.pkg.root_config.trees["bintree"]
	fetcher := NewBinpkgFetcher(b.background,
		b.scheduler.fetch.log_file, b.pkg, nil,
		b.scheduler)
	b.pkg_path = fetcher.pkg_path
	b._start_task(fetcher, b._fetcher_exit)
}

func (b *BinpkgPrefetcher) _fetcher_exit( fetcher) {
	if b._default_exit(fetcher) != 0 {
		b.wait()
		return
	}

	verifier := NewBinpkgVerifier( b.background,
		 b.scheduler.fetch.log_file, b.pkg,
		 b.scheduler, b.pkg_path)
	b._start_task(verifier, b._verifier_exit)
}

func (b *BinpkgPrefetcher) _verifier_exit(verifier ) {
	if b._default_exit(verifier) != 0 {
		b.wait()
		return
	}

	b._bintree.inject(b.pkg.cpv, b.pkg_path)

	b._current_task = nil
	i := 0
	b.returncode = &i
	b.wait()
}

func NewBinpkgPrefetcher(background bool, pkg *versions.PkgStr, scheduler *SchedulerInterface)*BinpkgPrefetcher {
	b := &BinpkgPrefetcher{}
	b.CompositeTask = NewCompositeTask()
	b.background = background
	b.pkg= pkg
	b.scheduler= scheduler

	return b
}

type BlockerCache struct {
	_cache_threshold int

	_vardb           *dbapi.vardbapi
	_cache_filename  string
	_cache_version   string
	_modified        map[string]bool
}

type BlockerData struct {
	// slot
	__weakref__,atoms,counter
}

func NewBlockerData(counter, atoms)*BlockerData {
	b := &BlockerData{}
	b.counter = counter
	b.atoms = atoms
	return b
}

func NewBlockerCache(myroot string, vardb *dbapi.vardbapi)*BlockerCache {
	b := &BlockerCache{}
	b._cache_threshold = 5

	b._vardb = vardb
	b._cache_filename = filepath.Join(vardb.settings.ValueDict["EROOT"], _const.CachePath, "vdb_blockers.pickle")
	b._cache_version = "1"
	b._cache_data = nil
	b._modified = map[string]bool{}
	b._load()
	return b
}

func (b *BlockerCache) _load() {
	//try:
	f, err := os.Open(b._cache_filename)
	mypickle :=ogórek.NewDecoder(f)
//try:
//	mypickle.find_global = nil
//	except AttributeError:
//	pass
	b._cache_data, _ = mypickle.Decode()
	f.Close()
	//except(SystemExit, KeyboardInterrupt):
	//raise
	//except Exception as e:
	//if isinstance(e, EnvironmentError) &&
	//	getattr(e, 'errno', nil)
	//	in(errno.ENOENT, errno.EACCES):
	//pass
	//else:
	//WriteMsg("!!! Error loading '%s': %s\n" %
	//	(b._cache_filename, str(e)), noiselevel = -1)
	//del e

	cache_valid := b._cache_data&&
		isinstance(b._cache_data, dict)&&
		b._cache_data.get("version") == b._cache_version&&
		isinstance(b._cache_data.get("blockers"), dict)
	if cache_valid {
		invalid_items := map[string]bool{}
		for k, versions.v
			in
		b._cache_data["blockers"].items() {
			//if not isinstance(k, basestring):
			//invalid_items.add(k)
			//continue
		//try:
			if versions.CatPkgSplit(k,1, "") == [4]string{} {
				invalid_items[k] = true
				continue
			}
			//except portage.exception.InvalidData:
			//invalid_items.add(k)
			//continue
			//if not isinstance(v, tuple) || len(v) != 2 {
			//	invalid_items[k] = true
			//	continue
			//}
			counter, atoms = versions.v
			if not isinstance(counter, (int, long)){
				invalid_items[k] = true
				continue
			}
			if not isinstance(atoms, (list, tuple)){
				invalid_items[k] = true
				continue
			}
			invalid_atom := false
			for atom
				in
			atoms {
				if not isinstance(atom, basestring) {
					invalid_atom = true
					break
				}
				if atom[:1] != "!" ||!dep.isValidAtom(
					atom, allow_blockers = true){
					invalid_atom = true
					break
				}
			}
			if invalid_atom {
				invalid_items[k] = true
				continue
			}
		}

		for k:= range invalid_items {
			del
			b._cache_data["blockers"][k]
		}
		if not b._cache_data["blockers"] {
			cache_valid = false
		}
	}

	if !cache_valid {
		b._cache_data =
		{
			"version":b._cache_version
		}
		b._cache_data["blockers"] =
		{
		}
	}
	b._modified = map[string]bool{}
}

func (b *BlockerCache) flush() {
	if len(b._modified) >= b._cache_threshold && *data.secpass >= 2:
//try:
	f := util.NewAtomic_ofstream(b._cache_filename, os.O_RDWR|os.O_TRUNC|os.O_CREATE, true)
	ogórek.NewEncoder(f).Encode(b._cache_data)
	f.Close()
	util.apply_secpass_permissions(
		b._cache_filename, -1, *data.portage_gid, 0644, -1, nil, nil)
	//except(IOError, OSError):
	//pass
	b._modified= map[string]bool{}
}

func (b *BlockerCache)  __setitem__( cpv string, blocker_data) {
	b._cache_data["blockers"][cpv] = (blocker_data.counter,
		tuple(_unicode(x)
	for x
		in
	blocker_data.atoms))
	b._modified[cpv] = true
}

func (b *BlockerCache)  __iter__() []{
	if b._cache_data == nil {
		return []
	}
	return b._cache_data["blockers"]
}

func (b *BlockerCache)  __len__() int {
	return len(b._cache_data["blockers"])
}

func (b *BlockerCache)  __delitem__(versions.cpv) {
	delete(b._cache_data["blockers"], versions.cpv)
}

func (b *BlockerCache)  __getitem__(versions.cpv) *BlockerData {
	return NewBlockerData(*b._cache_data["blockers"][versions.cpv])
}

type BlockerDB struct{
	_vartree *dbapi.varTree
	_portdb *dbapi.portdbapi
	_dep_check_trees *portage.TreesDict
	_root_config  ,_fake_vartree string
}

func NewBlockerDB( fake_vartree)*BlockerDB {
	b := &BlockerDB{}
	root_config := fake_vartree._root_config
	b._root_config = root_config
	b._vartree = root_config.trees["vartree"]
	b._portdb = root_config.trees["porttree"].dbapi

	b._dep_check_trees = nil
	b._fake_vartree = fake_vartree
	b._dep_check_trees = &portage.TreesDict{
		valueDict: map[string]*portage.Tree{b._vartree.settings.ValueDict["EROOT"]:
		&portage.Tree{
			_porttree: fake_vartree,
			_vartree:  fake_vartree,
		},
		},
		_running_eroot: "",
		_target_eroot:  "",
	}
	return b
}

func (b *BlockerDB)findInstalledBlockers( new_pkg) {
	blocker_cache := NewBlockerCache("",
		b._vartree.dbapi)
	dep_keys := structs.NewPackage().runtimeKeys
	settings := b._vartree.settings
	stale_cache := set(blocker_cache)
	fake_vartree := b._fake_vartree
	dep_check_trees := b._dep_check_trees
	vardb := fake_vartree.dbapi
	installed_pkgs := list(vardb)

	for _, inst_pkg := range installed_pkgs {
		stale_cache.discard(inst_pkg.cpv)
		cached_blockers := blocker_cache.get(inst_pkg.cpv)
		if cached_blockers != nil &&
			cached_blockers.counter != inst_pkg.counter {
			cached_blockers = nil
		}
		if cached_blockers != nil {
			blocker_atoms = cached_blockers.atoms
		} else {
			depstr := strings.Join(vardb.aux_get(inst_pkg.cpv, dep_keys), " ")
			success, atoms := dep.dep_check(depstr,
				vardb, settings, "yes", inst_pkg.use.enabled, 1, 0,
				inst_pkg.root, dep_check_trees)
			if success == 0 {
				pkg_location := filepath.Join(inst_pkg.root,
					_const.VdbPath, inst_pkg.category, inst_pkg.pf)
				msg.WriteMsg(fmt.Sprintf("!!! %s/*DEPEND: %s\n",
					pkg_location, atoms), -1, nil)
				continue
			}

			blocker_atoms := [][]*dep.Atom{{}}
			for _, atom := range atoms {
				if strings.HasPrefix(atom, "!") {
					blocker_atoms[0] = append(blocker_atoms[0], atom)
				}
			}
			blocker_atoms.sort()
			blocker_cache[inst_pkg.cpv] =
				blocker_cache.BlockerData(inst_pkg.counter, blocker_atoms)
		}
	}
	for cpv := range stale_cache {
		delete(blocker_cache, cpv)
	}
	blocker_cache.flush()

	blocker_parents := bad2.NewDigraph()
	blocker_atoms1 := []*dep.Atom{}
	for _, pkg := range installed_pkgs {
		for blocker_atom
			in
		blocker_cache.__getitem__(pkg.cpv).atoms
		{
			blocker_atom = blocker_atom.lstrip("!")
			blocker_atoms1 = append(blocker_atoms1, blocker_atom)
			blocker_parents.add(blocker_atom, pkg)
		}
	}

	blocker_atoms := sets.NewInternalPackageSet(blocker_atoms, false, true)
	blocking_pkgs = map[string]string{}
	for atom
		in
	blocker_atoms.iterAtomsForPackage(new_pkg)
	{
		blocking_pkgs.update(blocker_parents.parent_nodes(atom))
	}

	depstr := " ".join(new_pkg._metadata[k]
	for k
		in
	dep_keys)
	success, atoms := dep.dep_check(depstr,
		vardb, settings, "yes", new_pkg.use.enabled, 1, 0,
		0, new_pkg.root, dep_check_trees)
	if success == 0 {
		show_invalid_depstring_notice(new_pkg, atoms)
		assert
		false
	}

	blocker_atoms = [atom.lstrip("!")
	for atom
		in
	atoms
	if atom[:1] == "!"]
if blocker_atoms{
blocker_atoms = NewInternalPackageSet(initial_atoms = blocker_atoms)
for inst_pkg in installed_pkgs{
//try{
next(blocker_atoms.iterAtomsForPackage(inst_pkg))
//except (portage.exception.InvalidDependString, StopIteration){
//continue
//blocking_pkgs.add(inst_pkg)
}
}
return blocking_pkgs
}

func (b *BlockerDB)discardBlocker(versions.pkg) {
	a, _ := dep.NewAtom(fmt.Sprintf("=%s", versions.pkg.cpv, ), nil, false, nil, nil, "", nil, nil)
	for cpv_match
		in
	b._fake_vartree.dbapi.match_pkgs(a)
	{
		if cpv_match.cp == versions.pkg.cp {
			b._fake_vartree.cpv_discard(cpv_match)
		}
	}
	for slot_match
		in
	b._fake_vartree.dbapi.match_pkgs(versions.pkg.slot_atom)
	{
		if slot_match.cp == versions.pkg.cp {
			b._fake_vartree.cpv_discard(slot_match)
		}
	}
}

type DepPriority struct{
	*AbstractDepPriority

	// slot
	satisfied, optional, ignored
}

func(d*DepPriority) __int__() int {
	if d.optional {
		return -4
	}
	if d.buildtime_slot_op {
		return 0
	}
	if d.buildtime {
		return -1
	}
	if d.runtime {
		return -2
	}
	if d.runtime_post {
		return -3
	}
	return -5
}

func(d *DepPriority) __str__() string {
	if d.ignored {
		return "ignored"
	}
	if d.optional {
		return "optional"
	}
	if d.buildtime_slot_op {
		return "buildtime_slot_op"
	}
	if d.buildtime {
		return "buildtime"
	}
	if d.runtime_slot_op {
		return "runtime_slot_op"
	}
	if d.runtime {
		return "runtime"
	}
	if d.runtime_post {
		return "runtime_post"
	}
	return "soft"
}

func NewDepPriority(buildTime bool)*DepPriority {
	d := &DepPriority{}
	d.AbstractDepPriority = &AbstractDepPriority{}
	d.buildtime = buildTime
	return d
}

type EbuildBinpkg struct {
	*CompositeTask
	// slot
	settings *config.Config
	_binpkg_tmpfile string
	versions.pkg, _binpkg_info
}

func (e *EbuildBinpkg) _start() {
	pkg := e.pkg
	root_config := pkg.root_config
	bintree := root_config.trees["bintree"]
	binpkg_tmpfile := filepath.Join(bintree.pkgdir,
		pkg.cpv+".tbz2."+fmt.Sprint(os.Getpid()))
	bintree._ensure_dir(filepath.Dir(binpkg_tmpfile))

	e._binpkg_tmpfile = binpkg_tmpfile
	e.settings.ValueDict["PORTAGE_BINPKG_TMPFILE"] = e._binpkg_tmpfile

	package_phase := NewEbuildPhase(nil, e.background, "package", e.scheduler, e.settings, nil)

	e._start_task(package_phase, e._package_phase_exit)
}

func (e *EbuildBinpkg) _package_phase_exit( package_phase) {

	delete(e.settings.ValueDict,"PORTAGE_BINPKG_TMPFILE")
	if e._default_exit(package_phase) != 0 {
		if err := syscall.Unlink(e._binpkg_tmpfile); err != nil {
			//except OSError:
			//pass
		}
		e.wait()
		return
	}

	pkg := e.pkg
	bintree := pkg.root_config.trees["bintree"]
	e._binpkg_info = bintree.inject(pkg.cpv,
		filename = e._binpkg_tmpfile)

	e._current_task = nil
	i := 0
	e.returncode = &i
	e.wait()
}

func (e *EbuildBinpkg) get_binpkg_info() {
	return e._binpkg_info
}

func NewEbuildBinpkg(background bool, pkg *versions.PkgStr, scheduler *SchedulerInterface, settings *config.Config)*EbuildBinpkg {
	e := &EbuildBinpkg{}
	e.CompositeTask = NewCompositeTask()
	e.background = background
	e.pkg= pkg
	e.scheduler=scheduler
	e.settings=settings

	return e
}

type _RecordBinpkgInfo struct {
	*AsynchronousTask
	//slot
	ebuild_binpkg *EbuildBinpkg
	ebuild_build  *EbuildBuild
}

func (r *_RecordBinpkgInfo) _start() {
	r.ebuild_build._record_binpkg_info(r.ebuild_binpkg)
	r.AsynchronousTask._start()
}

func NewRecordBinpkgInfo(ebuild_binpkg *EbuildBinpkg, ebuild_build *EbuildBuild)*_RecordBinpkgInfo {
	r := &_RecordBinpkgInfo{}
	r.AsynchronousTask = NewAsynchronousTask()
	r.ebuild_binpkg = ebuild_binpkg
	r.ebuild_build = ebuild_build
	return r
}

func (r *EbuildBuild)	_buildpkg_exit( packager){

	if r._default_exit(packager) != 0 {
		r._async_unlock_builddir(r.returncode)
		return
	}

	if r.opts.buildpkgonly {
		phase := "success_hooks"
		success_hooks := NewMiscFunctionsProcess(
			r.background, []string{phase}, phase, "", nil,
			r.scheduler, r.settings)
		r._start_task(success_hooks,
			r._buildpkgonly_success_hook_exit)
		return
	}

	r._current_task = nil
	r.returncode = packager.returncode
	r.wait()
}

func (r *EbuildBuild) _record_binpkg_info( task) {
	if task.returncode != 0 {
		return
	}

	pkg := task.get_binpkg_info()
	infoloc := filepath.Join(r.settings.ValueDict["PORTAGE_BUILDDIR"],
		"build-info")
	info := map[string]string{
		"BINPKGMD5": fmt.Sprintf("%s\n", pkg._metadata["MD5"]),
	}
	if pkg.build_id != nil {
		info["BUILD_ID"] = fmt.Sprintf("%s\n", pkg.build_id)
	}
	for k, v := range info {
		f, _ := os.OpenFile(filepath.Join(infoloc, k), os.O_RDWR|os.O_CREATE, 0644)
		f.Write([]byte(v))
	}
}

func (r *EbuildBuild) _buildpkgonly_success_hook_exit( success_hooks) {
	r._default_exit(success_hooks)
	r.returncode = nil
	elog.elog_process(r.pkg.cpv.string, r.settings, nil)
	phase := "clean"
	clean_phase := NewEbuildPhase(nil, r.background, phase,r.scheduler, r.settings, nil)
	r._start_task(clean_phase, r._clean_exit)
}

func (r *EbuildBuild) _clean_exit( clean_phase) {
	if r._final_exit(clean_phase) != 0 || r.opts.buildpkgonly {
		r._async_unlock_builddir(r.returncode)
	} else {
		r.wait()
	}
}

func (r *EbuildBuild) create_install_task() *EbuildMerge {

	ldpath_mtimes := r.ldpath_mtimes
	logger := r.logger
	pkg := r.pkg
	pkg_count := r.pkg_count
	settings := r.settings
	world_atom := r.world_atom
	ebuild_path := r._ebuild_path
	tree := r._tree

	task := NewEbuildMerge(r._install_exit,
		r.find_blockers, ldpath_mtimes, logger, pkg,
		pkg_count, ebuild_path, r.scheduler, settings, tree, world_atom)

	msg := fmt.Sprintf(" === (%s of %s) Merging (%s::%s)",
		pkg_count.curval, pkg_count.maxval,
		pkg.cpv, ebuild_path)
	short_msg := fmt.Sprintf("emerge: (%s of %s) %s Merge",
		pkg_count.curval, pkg_count.maxval, pkg.cpv)
	logger.log(msg, short_msg = short_msg)

	return task
}

func (r *EbuildBuild) _install_exit(task) interfaces.IFuture {
	r._async_unlock_builddir(nil)
	var result interfaces.IFuture
	if r._current_task == nil {
		result = r.scheduler.create_future()
		r.scheduler.call_soon(func() {result.set_result(0)})
	}else {
		result = r._current_task.async_wait()
	}
	return result
}

//
func NewEbuildBuild(args_set = args_set,
	background = m.background,
	config_pool=m.config_pool,
	find_blockers = find_blockers,
	ldpath_mtimes=ldpath_mtimes, logger = logger,
	opts=build_opts, versions.pkg = pkg, pkg_count=pkg_count,
	prefetcher = m.prefetcher, scheduler=scheduler,
	settings = settings, world_atom=world_atom)*EbuildBuild {
	e := &EbuildBuild{}
	e.CompositeTask= NewCompositeTask()
	return e
}

type EbuildBuildDir struct {
	// slot
	scheduler *SchedulerInterface
	_catdir string
	_lock_obj *AsynchronousLock
	settings *config.Config
	locked bool
}

func NewEbuildBuildDir(scheduler *SchedulerInterface, settings *config.Config **kwargs)*EbuildBuildDir {
	e := &EbuildBuildDir{}
	e.scheduler = scheduler
	e.settings = settings
	e.locked = false

	return e
}

func (e*EbuildBuildDir) _assert_lock( async_lock *AsynchronousLock) error {
	if async_lock.returncode == nil || *async_lock.returncode != 0 {
		//raise AssertionError("AsynchronousLock failed with returncode %s"
		//% (async_lock.returncode,))
		return errors.New("")
	}
	return nil
}

func (e*EbuildBuildDir) clean_log() {
	settings := e.settings
	if settings.Features.Features["keepwork"] {
		return
	}
	log_file := settings.ValueDict["PORTAGE_LOG_FILE"]
	if log_file != "" {
		st, err := os.Stat(log_file)
		if err != nil && !st.IsDir() {
			if err := syscall.Unlink(log_file); err != nil {
				//except OSError:
				//pass
			}
		}
	}
}

func (e*EbuildBuildDir) async_lock() interfaces.IFuture {
	if e._lock_obj != nil {
		//raise
		//e.AlreadyLocked((e._lock_obj, ))
	}

	dir_path := e.settings.ValueDict["PORTAGE_BUILDDIR"]
	if dir_path == "" {
		//raise
		//AssertionError('PORTAGE_BUILDDIR is unset')
	}
	catdir := filepath.Dir(dir_path)
	e._catdir = catdir
	catdir_lock := NewAsynchronousLock(catdir, e.scheduler)
	builddir_lock := NewAsynchronousLock(dir_path, e.scheduler)
	result := e.scheduler.create_future()

	// nil
	catdir_unlocked := func(future interfaces.IFuture, exception error) {
		if !(exception == nil && future.exception() == nil) {
			if exception != nil {
				result.set_exception(exception)
			} else {
				result.set_exception(future.exception())
			}
		} else {
			result.set_result(nil)
		}
	}

	builddir_locked := func(builddir_lock *AsynchronousLock) {
		if err := e._assert_lock(builddir_lock); err != nil {
			//except AssertionError as e:
			catdir_lock.async_unlock().add_done_callback(
				catdir_unlocked) // exception = e
			return
		}

		e._lock_obj = builddir_lock
		e.locked = true
		e.settings.ValueDict["PORTAGE_BUILDDIR_LOCKED"] = "1"
		catdir_lock.async_unlock().add_done_callback(catdir_unlocked)
	}

	catdir_locked := func(catdir_lock*AsynchronousLock) {
		if err:=e._assert_lock(catdir_lock); err!= nil {
			//except AssertionError as e:
			result.set_exception(err)
			return
		}

		//try:
		util.EnsureDirs(catdir, -1, *data.portage_gid, 070, 0, nil, true)
		//except PortageException as e:
		//if ! filepath.Dir(catdir) {
		//	result.set_exception(e)
		//	return
		//}

		builddir_lock.addExitListener(builddir_locked)
		builddir_lock.start()
	}

	//try:
	util.EnsureDirs(filepath.Dir(catdir), -1, *data.portage_gid, 070, 0, nil, true)
	//except PortageException:
	//if not filepath.Dir(filepath.Dir(catdir)):
	//raise

	catdir_lock.addExitListener(catdir_locked)
	catdir_lock.start()
	return result
}

func (e*EbuildBuildDir) async_unlock() interfaces.IFuture {
	result := e.scheduler.create_future()

	catdir_unlocked := func(future interfaces.IFuture) {
		if future.exception() == nil {
			result.set_result(nil)
		} else {
			result.set_exception(future.exception())
		}
	}

	catdir_locked := func(catdir_lock *AsynchronousLock) {
		if catdir_lock.wait() != 0 {
			result.set_result(nil)
		} else {
			if err := os.RemoveAll(e._catdir); err != nil {
				//except OSError:
				//pass
			}
			catdir_lock.async_unlock().add_done_callback(func(future interfaces.IFuture, err error) {
				catdir_unlocked(future)
			})
		}
	}

	builddir_unlocked := func(future interfaces.IFuture) {
		if future.exception() != nil {
			result.set_exception(future.exception())
		} else {
			e._lock_obj = nil
			e.locked = false
			delete(e.settings.ValueDict, "PORTAGE_BUILDDIR_LOCKED")
			catdir_lock := NewAsynchronousLock(e._catdir, e.scheduler)
			catdir_lock.addExitListener(catdir_locked)
			catdir_lock.start()
		}
	}

	if e._lock_obj == nil {
		e.scheduler.call_soon(func() { result.set_result(nil) })
	} else {
		e._lock_obj.async_unlock().add_done_callback(func(future interfaces.IFuture, err error) {
			builddir_unlocked(future)
		})
	}
	return result
}

type AlreadyLocked struct {
	exception.PortageException
}

type EbuildExecuter struct {
	*CompositeTask
	// slot
	pkg *versions.PkgStr
	settings *config.Config
}

var _phases = []string{"prepare", "configure", "compile", "test", "install"}

func (e*EbuildExecuter)_start() {
	pkg := e.pkg
	scheduler := e.scheduler
	settings := e.settings
	cleanup := 0
	ebuild2.Prepare_build_dirs(settings, cleanup!=0)

	if eapi2.EapiExportsReplaceVars(settings.ValueDict["EAPI"]) {
		vardb := pkg.root_config.trees['vartree'].dbapi
		settings.ValueDict["REPLACING_VERSIONS"] = " ".join(
			set(versions.cpvGetVersion(match, "") \
		for match
			in
		vardb.match(pkg.slot_atom) + \
		vardb.match('=' + pkg.cpv)))

		setup_phase := NewEbuildPhase(nil, e.background, "setup", scheduler, settings, nil)

		setup_phase.addExitListener(e._setup_exit)
		e._task_queued(setup_phase)
		e.scheduler.scheduleSetup(setup_phase)
	}
}

func (e*EbuildExecuter) _setup_exit( setup_phase) {

	if e._default_exit(setup_phase) != 0 {
		e.wait()
		return
	}

	unpack_phase := NewEbuildPhase(nil, e.background, "unpack", e.scheduler, e.settings, nil)

	if myutil.Ins(strings.Fields(
		e.settings.ValueDict["PROPERTIES"]), "live") {

		unpack_phase.addExitListener(e._unpack_exit)
		e._task_queued(unpack_phase)
		e.scheduler.scheduleUnpack(unpack_phase)

	} else {
		e._start_task(unpack_phase, e._unpack_exit)
	}
}

func (e*EbuildExecuter) _unpack_exit( unpack_phase) {

	if e._default_exit(unpack_phase) != 0 {
		e.wait()
		return
	}

	ebuild_phases := NewTaskSequence(e.scheduler)

	versions.pkg = e.pkg
	phases := e._phases
	eapi := versions.pkg.eapi
	if ! eapi2.eapiHasSrcPrepareAndSrcConfigure(eapi) {
		phases = phases[2:]
	}

	for phase
	in
phases {
		ebuild_phases.add(NewEbuildPhase(nil, e.background, phase, e.scheduler, e.settings, nil))
	}

	e._start_task(ebuild_phases, e._default_final_exit)
}

func NewEbuildExecuter(background bool, pkg *versions.PkgStr, scheduler *SchedulerInterface, settings *config.Config)*EbuildExecuter {
	e := &EbuildExecuter{}
	e.CompositeTask = NewCompositeTask()
	e.background = background
	e.pkg = pkg
	e.scheduler = scheduler
	e.settings = settings
	return e
}


type EbuildFetchonly struct {
	settings *config.Config
	pretend int
	pkg *versions.PkgStr
	fetch_all,
}

func (e *EbuildFetchonly) execute() int {
	settings := e.settings
	pkg := e.pkg
	portdb := pkg.root_config.trees["porttree"].dbapi
	ebuild_path := portdb.findname(pkg.cpv, myrepo = pkg.repo)
	if ebuild_path == "" {
		raise AssertionError("ebuild not found for '%s'" % pkg.cpv)
	}
	settings.SetCpv(pkg)
	debug := settings.ValueDict["PORTAGE_DEBUG"] == "1"

	rval := atom.doebuild(ebuild_path, "fetch", settings, debug, e.pretend,
		1, 0, 1, e.fetch_all,"porttree", portdb, nil, nil, nil, false )

	if rval != 1 && e.pretend == 0{
		msg := fmt.Sprintf("Fetch failed for '%s'" ,pkg.cpv, )
		elog.eerror(msg, "unpack", pkg.cpv.string, nil)
	}
	return rval
}

func NewEbuildFetchonly(fetch_all , pkg *versions.PkgStr, pretend int, settings *config.Config)*EbuildFetchonly {
	e := &EbuildFetchonly{}
	e.settings = settings

	e.fetch_all = fetch_all
	e.pkg = pkg
	e.pretend = pretend

	return e
}

type EbuildIpcDaemon struct {
	*FifoIpcDaemon
	commands map[string]ebuild2.IpcCommand
}

func (e *EbuildIpcDaemon) _input_handler() {
	data := e._read_buf(e._files.pipe_in)
	if data == nil {
		//pass
	}else if len(data) > 0 {
	try:
		obj = pickle.loads(data)
		except
	SystemExit:
		raise
		except
	Exception:
		pass
		else:

		e._reopen_input()

		cmd_key = obj[0]
		cmd_handler := e.commands[cmd_key]
		reply := cmd_handler.Call(obj)
	try:
		e._send_reply(reply)
		except
		OSError
		as
	e:
		if err == errno.ENXIO:
		pass
		else:
		raise

		reply_hook = getattr(cmd_handler,
			'reply_hook', nil)
		if reply_hook != nil:
		reply_hook()

	}else {
		lock_filename := filepath.Join(
			filepath.Dir(e.input_fifo), ".ipc_lock")
		lock_obj, err := locks.Lockfile(lock_filename, false, true, "", os.O_NONBLOCK)
		if err != nil {
			//except TryAgain:
			//pass
		}else {
			//try:
			e._reopen_input()
			//finally:
			locks.Unlockfile(lock_obj)
		}
	}
}

func (e *EbuildIpcDaemon) _send_reply( reply) {
	output_fd, err := os.OpenFile(e.output_fifo,
		os.O_WRONLY|syscall.O_NONBLOCK, 0644)
	if err != nil {
		//except OSError as e:
		msg.WriteMsgLevel(fmt.Sprintf("!!! EbuildIpcDaemon %s: %s\n",
			"failed to send reply", e), 40, -1)
	} else {
		//try:
		output_fd.Write(pickle.dumps(reply))
		//finally:
		output_fd.Close()
	}
}

func NewEbuildIpcDaemon(commands map[string]ebuild2.IpcCommand, input_fifo, output_fifo string, scheduler *SchedulerInterface) *EbuildIpcDaemon {
	e := &EbuildIpcDaemon{}
	e.FifoIpcDaemon = NewFifoIpcDaemon()
	e.commands = commands
	e.input_fifo = input_fifo
	e.output_fifo = output_fifo
	e.scheduler = scheduler
	return e
}

type EbuildMerge struct {
	*CompositeTask

	// slot
	settings *config.Config
	tree string
	exit_hook func()
	logger*_emerge_log_class
	pkg_count *_pkg_count_class
	pkg_path string
	world_atom func()
	 find_blockers,  ldpath_mtimes,
	pkg, postinst_failure, pretend
}

func (e*EbuildMerge) _start() {
	root_config := e.pkg.root_config
	settings := e.settings
	mycat := settings.ValueDict["CATEGORY"]
	mypkg := settings.ValueDict["PF"]
	pkgloc := settings.ValueDict["D"]
	infloc := filepath.Join(settings.ValueDict["PORTAGE_BUILDDIR"], "build-info")
	myebuild := settings.ValueDict["EBUILD"]
	mydbapi := root_config.trees[e.tree].dbapi
	vartree := root_config.trees["vartree"]
	background := settings.ValueDict["PORTAGE_BACKGROUND"] == "1"
	logfile := settings.ValueDict["PORTAGE_LOG_FILE"]

	merge_task := NewMergeProcess(
		mycat, mypkg, settings, e.tree, vartree, e.scheduler,
		background, e.find_blockers, pkgloc, infloc, myebuild, mydbapi,
		e.ldpath_mtimes, logfile, nil)

	e._start_task(merge_task, e._merge_exit)
}

func (e*EbuildMerge) _merge_exit( merge_task) {
	if e._final_exit(merge_task) != 0 {
		e._start_exit_hook(e.returncode)
		return
	}

	e.postinst_failure = merge_task.postinst_failure
	pkg := e.pkg
	e.world_atom(pkg)
	pkg_count := e.pkg_count
	pkg_path := e.pkg_path
	logger := e.logger
	if !e.settings.Features.Features["noclean"] {
		short_msg := fmt.Sprintf("emerge: (%s of %s) %s Clean Post",
			pkg_count.curval, pkg_count.maxval, pkg.cpv)
		logger.log(fmt.Sprintf(" === (%s of %s) Post-Build Cleaning (%s::%s)",
			pkg_count.curval, pkg_count.maxval, pkg.cpv, pkg_path), short_msg)
	}
	logger.log(fmt.Sprintf(" ::: completed emerge (%s of %s) %s to %s",
		pkg_count.curval, pkg_count.maxval, pkg.cpv, pkg.root), "")

	e._start_exit_hook(e.returncode)
}

func (e*EbuildMerge) _start_exit_hook(returncode *int) {
	e.returncode = nil
	e._start_task(
		NewAsyncTaskFuture(e.exit_hook(e)),
		func(task) { e._exit_hook_exit(returncode, task) })
}

func (e*EbuildMerge) _exit_hook_exit(returncode *int, task) {
	e._assert_current(task)
	e.returncode = returncode
	e._async_wait()
}

func NewEbuildMerge(exit_hook func(), find_blockers , ldpath_mtimes,
	logger *_emerge_log_class, pkg, pkg_count *_pkg_count_class,
	pkg_path string, scheduler *SchedulerInterface,
	settings *config.Config, tree string, world_atom func())*EbuildMerge {
	e := &EbuildMerge{}
	e.CompositeTask = NewCompositeTask()
	e.exit_hook = exit_hook
	e.find_blockers = find_blockers
	e.ldpath_mtimes = ldpath_mtimes
	e.logger = logger
	e.pkg = pkg
	e.pkg_count = pkg_count
	e.pkg_path = pkg_path
	e.scheduler = scheduler
	e.settings = settings
	e.tree = tree
	e.world_atom = world_atom

	return e
}

type EbuildMetadataPhase struct {
	*SubProcess
	_files *struct{ ebuild int}
	//slot
	_eapi,repo_path          string
	_eapi_lineno   int
	eapi_supported bool
	metadata map[string]string
	settings *config.Config
	fd_pipes map[int]int
	portdb *dbapi.portdbapi
	_raw_metadata []string
	versions.cpv, ebuild_hash,   write_auxdb
}

func(e *EbuildMetadataPhase) _start() {
	ebuild_path := e.ebuild_hash.location

	f, _ := ioutil.ReadFile(ebuild_path)
	e._eapi, e._eapi_lineno = portage.ParseEapiEbuildHead(strings.Split(string(f), "\n"))

	parsed_eapi := e._eapi
	if parsed_eapi == "" {
		parsed_eapi = "0"
	}

	if  parsed_eapi=="" {
		e._eapi_invalid(nil)
		i := 1
		e.returncode = &i
		e._async_wait()
		return
	}

	e.eapi_supported = eapi2.eapiIsSupported(parsed_eapi)
	if ! e.eapi_supported {
		e.metadata =map[string]string{
			"EAPI": parsed_eapi,
		}
		i:= 0
		e.returncode =&i
		e._async_wait()
		return
	}

	settings := e.settings
	settings.SetCpv(e.cpv)
	settings.configDict["pkg"]["EAPI"] = parsed_eapi

	debug := settings.ValueDict["PORTAGE_DEBUG"] == "1"
	var fd_pipes map[int]int
	if e.fd_pipes != nil {
		fd_pipes = map[int]int{}
		for k, v := range e.fd_pipes{
			fd_pipes[k]=v
		}
	}else {
		fd_pipes = map[int]int{}
	}

	null_input, _ := os.Open("/dev/null")
	if _, ok := fd_pipes[0];!ok {
		fd_pipes[0] = int(null_input.Fd())
	}
	if _, ok := fd_pipes[1];!ok {
		fd_pipes[1] = syscall.Stdout
	}
	if _, ok := fd_pipes[2];!ok {
		fd_pipes[2] = syscall.Stderr
	}

	for _, fd:= range fd_pipes {
		if fd == syscall.Stdout||fd ==syscall.Stderr{
			break
		}
	}

	e._files = &struct{ebuild int}{}
	files := e._files

	pps := make([]int,2)
	syscall.Pipe(pps)
	master_fd, slave_fd := pps[0],pps[1]

	arg, _ := unix.FcntlInt(uintptr(master_fd),syscall.F_GETFL, 0)
	unix.FcntlInt(uintptr(master_fd), syscall.F_SETFL, arg|syscall.O_NONBLOCK)

	arg2, _ := unix.FcntlInt(uintptr(master_fd),syscall.F_GETFD, 0)
	unix.FcntlInt(uintptr(master_fd), syscall.F_SETFD, arg2|syscall.FD_CLOEXEC)

	fd_pipes[slave_fd] = slave_fd
	settings.ValueDict["PORTAGE_PIPE_FD"] = fmt.Sprint(slave_fd)

	e._raw_metadata = []string{}
	files.ebuild = master_fd
	e.scheduler.add_reader(files.ebuild, e._output_handler)
	e._registered = true

	retval := atom.doebuild(ebuild_path, "depend",
		settings, debug, 0, 0, 0, 1, 0,
		"porttree", e.portdb, nil, nil, fd_pipes, true)
	delete(settings.ValueDict,"PORTAGE_PIPE_FD")

	syscall.Close(slave_fd)
	null_input.Close()

	//if isinstance(retval, int):
	e.returncode = &retval
	e._async_wait()
	return

	//e.pid = retval[0]
}

func(e *EbuildMetadataPhase) _output_handler() {
	for{
		buf := e._read_buf(e._files.ebuild)
		if buf == nil {
			break
		}else if len(buf) > 0 {
			e._raw_metadata=append(e._raw_metadata, string(buf))
		}else {
			if e.pid == 0 {
				e._unregister()
				e._async_wait()
			}else {
				e._async_waitpid()
			}
			break
		}
	}
}

func(e *EbuildMetadataPhase) _unregister() {
	if e._files != nil {
		e.scheduler.remove_reader(e._files.ebuild)
	}
	e.SubProcess._unregister()
}

func(e *EbuildMetadataPhase) _async_waitpid_cb( *args, **kwargs) {
	e.SubProcess._async_waitpid_cb(*args, **kwargs)
	if e.returncode != nil && *e.returncode == 0 && e._raw_metadata != nil {
		metadata_lines := strings.Split(strings.Join(e._raw_metadata, ""), "\n")
		metadata_valid := true
		metadata := map[string]string{}
		if len(atom.auxdbkeys) != len(metadata_lines) {
			metadata_valid = false
		} else {
			adk := myutil.sortedmsb(atom.auxdbkeys)
			for i := range adk {
				metadata[adk[i]] = metadata_lines[i]
			}
			parsed_eapi := e._eapi
			if parsed_eapi == "" {
				parsed_eapi = "0"
			}
			e.eapi_supported = eapi2.eapiIsSupported(metadata["EAPI"])
			if (metadata["EAPI"] == "" || e.eapi_supported) && metadata["EAPI"] != parsed_eapi {
				e._eapi_invalid(metadata)
				metadata_valid = false
			}
		}

		if metadata_valid {
			if e.eapi_supported {
				if metadata["INHERITED"] != "" {
					metadata["_eclasses_"] = e.portdb.repositories.GetRepoForLocation(
						e.repo_path).eclassDb.get_eclass_data(
						metadata["INHERITED"].split())
				} else {
					metadata["_eclasses_"] =
					{
					}
				}
				delete(metadata, "INHERITED")

				if eapi2.eapiHasAutomaticUnpackDependencies(metadata["EAPI"]) {
					repo := e.portdb.repositories.getNameForLocation(e.repo_path)
					unpackers := e.settings.unpackDependencies[repo][metadata["EAPI"]]
					unpack_dependencies := dep.extractUnpackDependencies(metadata["SRC_URI"], unpackers)
					if unpack_dependencies != "" {
						if metadata["DEPEND"] != "" {
							metadata["DEPEND"] += " "
						}
						metadata["DEPEND"] += unpack_dependencies
					}
				}

				if e.write_auxdb is
				not
				false{
					e.portdb._write_cache(e.cpv,
						e.repo_path, metadata, e.ebuild_hash)
				}
			} else {
				metadata = map[string]string{
					"EAPI": metadata["EAPI"],
				}
			}
			e.metadata = metadata
		} else {
			i := 1
			e.returncode = &i
		}
	}
}

func(e *EbuildMetadataPhase) _eapi_invalid( metadata map[string]string) {
	repo_name := e.portdb.getRepositoryName(e.repo_path)
	eapi_var := ""
	if metadata!= nil {
		eapi_var = metadata["EAPI"]
	}
	eapi_invalid(e, e.cpv, repo_name, e.settings,
		eapi_var, e._eapi, e._eapi_lineno)
}

func NewEbuildMetadataPhase(cpv string, ebuild_hash, portdb dbapi.portdbapi, repo_path string, scheduler = loop, settings *config.Config)*EbuildMetadataPhase {
	e := &EbuildMetadataPhase{}
	e.SubProcess = NewSubProcess()
	e.cpv = cpv
	e.ebuild_hash = ebuild_hash
	e.portdb = portdb
	e.repo_path = repo_path
	e.scheduler = scheduler
	e.settings = settings
	return e
}

type EbuildPhase struct {
	*CompositeTask

	// slot
	actionmap ebuild2.Actionmap
	phase     string
	_ebuild_lock *AsynchronousLock
	settings     *config.Config
	fd_pipes     map[int]int

	_features_display []string
	_locked_phases    []string
}

func NewEbuildPhase(actionmap ebuild2.Actionmap, background bool, phase string, scheduler *SchedulerInterface, settings *config.Config, fd_pipes map[int]int) *EbuildPhase {	e := &EbuildPhase{}
	e._features_display = []string{
		"ccache", "compressdebug", "distcc", "fakeroot",
		"installsources", "keeptemp", "keepwork", "network-sandbox",
		"network-sandbox-proxy", "nostrip", "preserve-libs", "sandbox",
		"selinux", "sesandbox", "splitdebug", "suidctl", "test",
		"userpriv", "usersandbox",
	}
	e._locked_phases = []string{
		"setup", "preinst", "postinst", "prerm", "postrm",
	}

	e.actionmap = actionmap
	e.background = background
	e.phase = phase
	e.scheduler = scheduler
	e.settings = settings
	e.fd_pipes = fd_pipes

	return e
}

func (e *EbuildPhase) _start() {

	need_builddir := myutil.Ins(NewEbuildProcess(nil, false, nil, "", "", nil, nil)._phases_without_builddir, e.phase)

	if need_builddir {
		phase_completed_file :=
			filepath.Join(
				e.settings.ValueDict["PORTAGE_BUILDDIR"],
				fmt.Sprintf(".%sed", strings.TrimRight(e.phase,"e")))
		if ! myutil.PathExists(phase_completed_file) {

			err := syscall.Unlink(filepath.Join(e.settings.ValueDict["T"],
				"logging", e.phase))
			if err != nil {
				//except OSError{
				//pass
			}
		}
	}

	if e.phase =="nofetch" ||e.phase == "pretend"||e.phase == "setup" {
		use := e.settings.ValueDict["PORTAGE_BUILT_USE"]
		if use == "" {
			use = e.settings.ValueDict["PORTAGE_USE"]
		}

		maint_str := ""
		upstr_str := ""
		metadata_xml_path := filepath.Join(filepath.Dir(e.settings.ValueDict["EBUILD"]), "metadata.xml")
		if MetaDataXML != nil && myutil.pathIsFile(metadata_xml_path) {
			herds_path := filepath.Join(e.settings.ValueDict["PORTDIR"],
				"metadata/herds.xml")
			//try{
			metadata_xml = MetaDataXML(metadata_xml_path, herds_path)
			maint_str = metadata_xml.format_maintainer_string()
			upstr_str = metadata_xml.format_upstream_string()
			//except SyntaxError{
			//maint_str = "<invalid metadata.xml>"
		}

		msg := []string{}
		msg = append(msg, fmt.Sprintf("Package:    %s", e.settings.mycpv))
		if e.settings.ValueDict["PORTAGE_REPO_NAME"] != "" {
			msg = append(msg, fmt.Sprintf("Repository: %s", e.settings.ValueDict["PORTAGE_REPO_NAME"]))
		}
		if maint_str!= "" {
			msg = append(msg, fmt.Sprintf("Maintainer: %s", maint_str))
		}
		if upstr_str!= "" {
			msg = append(msg, fmt.Sprintf("Upstream:   %s", upstr_str))
		}

		msg = append(msg, fmt.Sprintf("USE:        %s", use))
		relevant_features := []string{}
		enabled_features := e.settings.Features.Features
		for _, x := range e._features_display {
			if enabled_features[ x]{
				relevant_features = append(relevant_features, x)
			}
		}
		if len(relevant_features) > 0 {
			msg = append(msg, fmt.Sprintf("FEATURES:   %s", strings.Join(relevant_features, " ")))
		}

		e._elog("einfo", msg, true)
	}

	if e.phase == "package" {
		if _, ok := e.settings.ValueDict["PORTAGE_BINPKG_TMPFILE"]; !ok{
			e.settings.ValueDict["PORTAGE_BINPKG_TMPFILE"] =
				filepath.Join(e.settings.ValueDict["PKGDIR"],
					e.settings.ValueDict["CATEGORY"], e.settings.ValueDict["PF"]) + ".tbz2"
		}
	}

	if e.phase  == "pretend" || e.phase ==  "prerm" {
		env_extractor := NewBinpkgEnvExtractor(e.background,
			e.scheduler, e.settings)
		if env_extractor.saved_env_exists() {
			e._start_task(env_extractor, e._env_extractor_exit)
			return
		}
	}

	e._start_lock()
}

func (e *EbuildPhase) _env_extractor_exit( env_extractor) {
	if e._default_exit(env_extractor) != 0 {
		e.wait()
		return
	}
	e._start_lock()
}

func (e *EbuildPhase) _start_lock() {
	if myutil.Ins(e._locked_phases, e.phase) &&
		e.settings.Features.Features["ebuild-locks"]{
		eroot := e.settings.ValueDict["EROOT"]
		lock_path := filepath.Join(eroot, _const.VdbPath+"-ebuild")
		if myutil.osAccess(filepath.Dir(lock_path), unix.W_OK) {
			e._ebuild_lock = NewAsynchronousLock(lock_path, e.scheduler)
			e._start_task(e._ebuild_lock, e._lock_exit)
			return
		}
	}

	e._start_ebuild()
}

func (e *EbuildPhase) _lock_exit( ebuild_lock) {
	if e._default_exit(ebuild_lock) != 0 {
		e.wait()
		return
	}
	e._start_ebuild()
}

func (e *EbuildPhase) _get_log_path() string {
	logfile := ""
	if e.phase != "clean" && e.phase != "cleanrm" &&
		e.settings.ValueDict["PORTAGE_BACKGROUND"] != "subprocess" {
		logfile = e.settings.ValueDict["PORTAGE_LOG_FILE"]
	}
	return logfile
}

func (e *EbuildPhase) _start_ebuild() {
	if e.phase == "package" {
		e._start_task(NewPackagePhase(e.actionmap, e.background, e.fd_pipes,
			e._get_log_path(), e.scheduler, e.settings), e._ebuild_exit)
		return
	}

	if e.phase == "unpack" {
		alist := strings.Fields(e.settings.configDict["pkg"]["A"])
		atom._prepare_fake_distdir(e.settings, alist)
		atom._prepare_fake_filesdir(e.settings)
	}

	fd_pipes := e.fd_pipes
	if fd_pipes == nil {
		if !e.background && e.phase == "nofetch" {
			fd_pipes = map[int]int{
				1: syscall.Stderr,
			}
		}
	}

	ebuild_process := NewEbuildProcess(e.actionmap,
		e.background, fd_pipes,
		e._get_log_path(), e.phase,
		e.scheduler, e.settings)

	e._start_task(ebuild_process, e._ebuild_exit)
}

func (e *EbuildPhase) _ebuild_exit( ebuild_process) {
	e._assert_current(ebuild_process)
	if e._ebuild_lock == nil {
		e._ebuild_exit_unlocked(ebuild_process)
	} else {
		e._start_task(
			NewAsyncTaskFuture( e._ebuild_lock.async_unlock()),
			functools.partial(e._ebuild_exit_unlocked, ebuild_process))
	}
}

func (e *EbuildPhase) _ebuild_exit_unlocked( ebuild_process, unlock_task=nil) {
	if unlock_task != nil {
		e._assert_current(unlock_task)
		if unlock_task.cancelled {
			e._default_final_exit(unlock_task)
			return
		}
		unlock_task.future.result()
	}

	fail := false
	if ebuild_process.returncode != 0 {
		e.returncode = ebuild_process.returncode
		if e.phase == "test" && e.settings.Features.Features["test-fail-continue"] {
			f, err := os.OpenFile(filepath.Join(
				e.settings.ValueDict["PORTAGE_BUILDDIR"], ".tested"), os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				//except OSError{
				//pass
			}
			f.Close()
		}else{
			fail = true
		}
	}

	if ! fail {
		e.returncode = nil
	}

	logfile := e._get_log_path()

	if e.phase == "install" {
		out := &bytes.Buffer{}
		atom._check_build_log(e.settings, out)
		msg := out.String()
		e.scheduler.output(msg, logfile, false, 0, -1)
	}

	if fail {
		e._die_hooks()
		return
	}

	settings := e.settings
	atom._post_phase_userpriv_perms(settings)

	if e.phase == "unpack" {
		syscall.Utime(settings.ValueDict["WORKDIR"], nil)
		atom._prepare_workdir(settings)
	} else if e.phase == "install" {
		out := &bytes.Buffer{}
		atom._post_src_install_write_metadata(settings)
		atom._post_src_install_uid_fix(settings, out)
		msg := out.String()
		if len(msg) > 0 {
			e.scheduler.output(msg, logfile, false, 0, -1)
		}
	} else if e.phase == "preinst" {
		atom._preinst_bsdflags(settings)
	} else if e.phase == "postinst" {
		atom._postinst_bsdflags(settings)
	}

	post_phase_cmds := atom._post_phase_cmds.get(e.phase)
	if post_phase_cmds != nil {
		if logfile != "" && e.phase =="install" {
			logfile , _ = os.MkdirTemp("","")
		}
		post_phase := NewPostPhaseCommands(e.background,
			post_phase_cmds, e._elog,  e.fd_pipes,
			logfile,  e.phase, e.scheduler, settings)
		e._start_task(post_phase, e._post_phase_exit)
		return
	}

	e.returncode = new(int)
	*e.returncode = 0
	e._current_task = nil
	e.wait()
}

func (e *EbuildPhase) _post_phase_exit( post_phase) {

	e._assert_current(post_phase)

	log_path := ""
	if e.settings.ValueDict["PORTAGE_BACKGROUND"] != "subprocess" {
		log_path = e.settings.ValueDict["PORTAGE_LOG_FILE"]
	}

	if post_phase.logfile != nil &&
		post_phase.logfile != log_path {
		e._append_temp_log(post_phase.logfile, log_path)
	}

	if e._final_exit(post_phase) != 0 {
		msg.WriteMsg(fmt.Sprintf("!!! post %s failed; exiting.\n", e.phase),
			-1, nil)
		e._die_hooks()
		return
	}

	e._current_task = nil
	e.wait()
	return
}

func (e *EbuildPhase) _append_temp_log( temp_log, log_path string) {

	temp_file, _ := ioutil.ReadFile(temp_log)

	log_file, log_file_real := e._open_log(log_path)

	for _, line:= range strings.Split(string(temp_file), "\n"){
		log_file.Write([]byte(line))
	}

	log_file.Close()
	if log_file_real != log_file {
		log_file_real.Close()
	}
	syscall.Unlink(temp_log)
}

func (e *EbuildPhase) _open_log( log_path string) (io.WriteCloser, io.WriteCloser) {
	var f, f_real io.WriteCloser
	f, _ = os.OpenFile(log_path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	f_real = f

	if strings.HasSuffix(log_path, ".gz") {
		f = gzip.NewWriter(f)
	}

	return f, f_real
}

func (e *EbuildPhase) _die_hooks() {
	e.returncode = nil
	phase := "die_hooks"
	die_hooks := NewMiscFunctionsProcess(e.background,
		[]string{phase},  phase, e._get_log_path(),
		e.fd_pipes, e.scheduler, e.settings)
	e._start_task(die_hooks, e._die_hooks_exit)
}

func (e *EbuildPhase) _die_hooks_exit( die_hooks) {
	if e.phase != "clean" &&
		!e.settings.Features.Features["noclean"] &&
		e.settings.Features.Features["fail-clean"] {
		e._default_exit(die_hooks)
		e._fail_clean()
		return
	}
	e._final_exit(die_hooks)
	e.returncode = new(int)
	*e.returncode = 1
	e.wait()
}

func (e *EbuildPhase) _fail_clean() {
	e.returncode = nil
	elog.elog_process(e.settings.mycpv.string, e.settings, nil)
	phase := "clean"
	clean_phase := NewEbuildPhase(nil, e.background, phase,  e.scheduler,
		e.settings, e.fd_pipes,)
	e._start_task(clean_phase, e._fail_clean_exit)
	return
}

func (e *EbuildPhase) _fail_clean_exit( clean_phase) {
	e._final_exit(clean_phase)
	e.returncode = new(int)
	*e.returncode = 1
	e.wait()
}

func (e *EbuildPhase) _elog( elog_funcname string, lines []string, background bool) {
	if background == false {
		background = e.background
	}
	out := &bytes.Buffer{}
	phase := e.phase

	var elog_func func(msg string, phase string, key string, out io.Writer)
	switch elog_funcname {
	case "eerror":
		elog_func = elog.eerror
	case "eqawarn":
		elog_func = elog.eqawarn
	case "einfo":
		elog_func = elog.einfo
	case "ewarn":
		elog_func = elog.ewarn
	case "elog":
		elog_func = elog.elog
	}

	global_havecolor := output.HaveColor
	//try{
	if myutil.Ins([]string{"no", "false", ""}, strings.ToLower(e.settings.ValueDict["NOCOLOR"])) {
		output.HaveColor = 1
	}else {
		output.HaveColor = 0
	}
	for _, line := range lines {
		elog_func(line, phase, e.settings.mycpv.string, out)
	}
	//finally{
	output.HaveColor = global_havecolor
	msg := out.String()
	if msg != "" {
		log_path := ""
		if e.settings.ValueDict["PORTAGE_BACKGROUND"] != "subprocess" {
			log_path = e.settings.ValueDict["PORTAGE_LOG_FILE"]
		}
		e.scheduler.output(msg, log_path, background, 0, -1)
	}
}

type _PostPhaseCommands struct {
	*CompositeTask

	// slots
	elog           func(string, []string, bool)
	fd_pipes       map[int]int
	logfile, phase string
	commands       []struct{ a map[string]string; b []string}
	settings       *config.Config
}

func(p*_PostPhaseCommands) _start() {
	//if isinstance(p.commands, list){
	//	cmds = []struct({}, p.commands)
	//}else{
	//cmds = list(p.commands)
	//}
	cmds := p.commands

	if !p.settings.Features.Features["selinux"] {
		cmds1 := []struct {
			a map[string]string;
			b []string
		}{}
		for _, c := range cmds {
			if c.a["selinux_only"] == "" {
				cmds1 = append(cmds1, c)
			}
		}
		cmds = cmds1
	}

	tasks := NewTaskSequence(nil)
	for _, v := range cmds {
		kwargs, commands := v.a, v.b

		kwargs1 := map[string]string{}
		for k, v:= range kwargs{
			if k == "ld_preload_sandbox" {
				kwargs1[k] = v
			}
		}
		tasks.add(NewMiscFunctionsProcess(p.background,
			commands, p.phase, p.logfile, p.fd_pipes,
			p.scheduler, p.settings, **kwargs))

		p._start_task(tasks, p._commands_exit)
	}
}

func(p*_PostPhaseCommands) _commands_exit( task) {

	if p._default_exit(task) != 0 {
		p._async_wait()
		return
	}

	if p.phase == "install" {
		out := &bytes.Buffer{}
		atom._post_src_install_soname_symlinks(p.settings, out)
		msg := out.String()
		if len(msg) > 0 {
			p.scheduler.output(msg, p.settings.ValueDict["PORTAGE_LOG_FILE"], false, 0, -1)
		}

		if p.settings.Features.Features["qa-unresolved-soname-deps"] {

			future := p._soname_deps_qa()

			future.add_done_callback(func(future interfaces.IFuture, err error) {
				//return
				//future.cancelled() || future.result()
			})
			p._start_task(NewAsyncTaskFuture(future), p._default_final_exit)
		} else {
			p._default_final_exit(task)
		}
	} else {
		p._default_final_exit(task)
	}
}

@coroutine
func(p*_PostPhaseCommands) _soname_deps_qa() interfaces.IFuture {

	vardb := ebuild2.NewQueryCommand(nil, "").get_db().Values()[p.settings.ValueDict["EROOT"]].VarTree().dbapi

	all_provides = (yield
	p.scheduler.run_in_executor(ForkExecutor(loop = p.scheduler), _get_all_provides, vardb))

	unresolved := _get_unresolved_soname_deps(filepath.Join(p.settings.ValueDict["PORTAGE_BUILDDIR"], "build-info"), all_provides)

	if len(unresolved) > 0 {
		unresolved.sort()
		qa_msg := []string{"QA Notice: Unresolved soname dependencies:"}
		qa_msg = append(qa_msg, "")
		qa_msg =append(qa_msg, fmt.Sprintf("\t%s: %s", filename, strings.Join(myutil.Sorted(soname_deps)), " "))
		for filename, soname_deps
			in
		unresolved)
		qa_msg= append(qa_msg, "")
		p.elog("eqawarn", qa_msg)
	}
}


// post_phase_cmds, nil, nil, logfile, e.phase, e.scheduler, nil
func NewPostPhaseCommands(background bool,
	commands = , elog func(string,[]string,bool), fd_pipes map[int]int,
	logfile string, phase string, scheduler *SchedulerInterface,
	settings *config.Config)*_PostPhaseCommands {
	p := &_PostPhaseCommands{}
	p.CompositeTask = NewCompositeTask()
	p.background = background
	p.commands = commands
	p.elog = elog
	p.fd_pipes = fd_pipes
	p.logfile = logfile
	p.phase = phase
	p.scheduler = scheduler
	p.settings = settings
	return p
}

type EbuildProcess struct {
	*AbstractEbuildProcess

	actionmap ebuild2.Actionmap
}

func (e *EbuildProcess) _spawn(args, **kwargs) ([]int, error) {
	actionmap := e.actionmap
	if actionmap == nil {
		actionmap = atom._spawn_actionmap(e.settings)
	}

	if e._dummy_pipe_fd != 0 {
		e.settings.ValueDict["PORTAGE_PIPE_FD"] = fmt.Sprint(e._dummy_pipe_fd)
	}

	defer delete(e.settings.ValueDict, "PORTAGE_PIPE_FD")
	return atom._doebuild_spawn(e.phase, e.settings, actionmap, **kwargs)
}

func NewEbuildProcess(actionmap ebuild2.Actionmap, background bool, fd_pipes map[int]int, logfile, phase string, scheduler *SchedulerInterface, settings *config.Config) *EbuildProcess {
	e := &EbuildProcess{}
	e.actionmap = actionmap
	e.AbstractEbuildProcess = NewAbstractEbuildProcess(actionmap, background, fd_pipes, logfile, phase, scheduler, settings)

	return e
}

type EbuildSpawnProcess struct {
	*AbstractEbuildProcess
	fakeroot_state string
	spawn_func     func()
}

var _spawn_kwarg_names = append(NewAbstractEbuildProcess()._spawn_kwarg_names ,"fakeroot_state",)

func (e *EbuildSpawnProcess)_spawn( args, **kwargs) {

	env := e.settings.environ()

	if e._dummy_pipe_fd != 0 {
		env["PORTAGE_PIPE_FD"] = fmt.Sprint(e._dummy_pipe_fd)
	}

	return e.spawn_func(args, env = env, **kwargs)
}

func NewEbuildSpawnProcess(background bool, args []string, scheduler *SchedulerInterface,
spawn_func = spawn_func, settings *config.Config, **keywords)*EbuildSpawnProcess {
	e := &EbuildSpawnProcess{}
	e.AbstractEbuildProcess = NewAbstractEbuildProcess()
	e.background = background
	e.args = args
	e.scheduler = scheduler
	e.spawn_func = spawn_func
	e.settings = settings
	return e
}

func FakeVardbGetPath(vardb *dbapi.vardbapi)func(string, string)string {
	return func(cpv, filename string) string {
		settings := vardb.settings
		path := filepath.Join(settings.ValueDict["EROOT"], _const.VdbPath, cpv)
		if filename != "" {
			path = filepath.Join(path, filename)
		}
		return path
	}
}

type _DynamicDepsNotApplicable struct {
	Exception
}

type FakeVartree struct {
	*vartree
	_dynamic_deps, _ignore_built_slot_operator_deps bool
	settings                                        *config.Config
	_db_keys, _portdb_keys                          []string
	_global_updates                                 map[string][][]string
	_portdb                                         *dbapi.portdbapi
	dbapi                                           *PackageVirtualDbapi
	_match                                          func(*dep.Atom, int)
}

// nil, nil, false, false, false
func NewFakeVartree(root_config, pkg_cache=None, pkg_root_config=None,
dynamic_deps, ignore_built_slot_operator_deps, soname_deps bool)*FakeVartree {
	f := &FakeVartree{}
	f.vartree = dbapi.NewVarTree()

	f._root_config = root_config
	f._dynamic_deps = dynamic_deps
	f._ignore_built_slot_operator_deps = ignore_built_slot_operator_deps
	if pkg_root_config is None{
		pkg_root_config = f._root_config
	}
	f._pkg_root_config = pkg_root_config
	if pkg_cache is None{
		pkg_cache ={}
	}
	real_vartree := root_config.trees["vartree"]
	f._real_vardb = real_vartree.dbapi
	portdb := root_config.trees["porttree"].dbapi
	f.settings = real_vartree.settings
	mykeys := list(real_vartree.dbapi._aux_cache_keys)
	if  !　myutil.Ins(mykeys, "_mtime_"){
		mykeys=append(mykeys, "_mtime_")
	}
	f._db_keys = mykeys
	f._pkg_cache = pkg_cache
	f.dbapi = NewPackageVirtualDbapi(real_vartree.settings)
	if soname_deps {
		f.dbapi = PackageDbapiProvidesIndex(f.dbapi)
	}
	f.dbapi.getpath = FakeVardbGetPath(f.dbapi)
	f.dbapi._aux_cache_keys = set(f._db_keys)

	f._aux_get = f.dbapi.aux_get
	f._match = f.dbapi.match
	if dynamic_deps {
		f.dbapi.aux_get = f._aux_get_wrapper
		f.dbapi.match = f._match_wrapper
	}
	f._aux_get_history = set()
	f._portdb_keys = structs.Package._dep_keys + ("EAPI", "KEYWORDS")
	f._portdb = portdb
	f._global_updates = None

	return f
}

// 1
func(f*FakeVartree) _match_wrapper(cpv, use_cache int) {
	matches = f._match(cpv, use_cache)
	for cpv in matches{
		if cpv in f._aux_get_history{
		continue
	}
		f._aux_get_wrapper(cpv, [])
	}
	return matches
}

func(f*FakeVartree) _aux_get_wrapper(versions.cpv, wants, myrepo=None) {
	if versions.cpv in
	f._aux_get_history{
		return f._aux_get(cpv, wants)
	}
	f._aux_get_history.add(versions.cpv)

	versions.pkg = f.dbapi._cpv_map[versions.cpv]

try:
	live_metadata = dict(zip(f._portdb_keys,
		f._portdb.aux_get(versions.cpv, f._portdb_keys,
			myrepo = versions.pkg.repo)))
	except(KeyError, portage.exception.PortageException):
	live_metadata = None

	f._apply_dynamic_deps(versions.pkg, live_metadata)

	return f._aux_get(versions.cpv, wants)
}

func(f*FakeVartree) _apply_dynamic_deps(versions.pkg, live_metadata) {

try:
	if live_metadata  ==nil {
		raise
		_DynamicDepsNotApplicable()
	}
	if !(eapi2.eapiIsSupported(live_metadata["EAPI"]) && eapi2.eapiIsSupported(versions.pkg.eapi)) {
		raise
		_DynamicDepsNotApplicable()
	}

	built_slot_operator_atoms = None
	if ! f._ignore_built_slot_operator_deps && eapi2.getEapiAttrs(versions.pkg.eapi).slotOperator {
	try:
		built_slot_operator_atoms = \
		find_built_slot_operator_atoms(versions.pkg)
		except
	InvalidDependString:
		pass
	}

	if built_slot_operator_atoms{
	live_eapi_attrs = _get_eapi_attrs(live_metadata["EAPI"])
	if ! live_eapi_attrs.slot_operator {
		raise
		_DynamicDepsNotApplicable()
	}
	for k, versions.v
	in
	built_slot_operator_atoms.items(){
	live_metadata[k] += (" " +
		" ".join(_unicode(atom)
		for atom
			in
		versions.v))
	}
	}

	f.dbapi.aux_update(versions.pkg.cpv, live_metadata)
	except
_DynamicDepsNotApplicable:
	if f._global_updates == nil {
		f._global_updates = grab_global_updates(f._portdb)
	}

	aux_keys = structs.Package._dep_keys + f.dbapi._pkg_str_aux_keys
	aux_dict = dict(zip(aux_keys, f._aux_get(versions.pkg.cpv, aux_keys)))
	perform_global_updates(
		versions.pkg.cpv, aux_dict, f.dbapi, f._global_updates)
}

func(f*FakeVartree) dynamic_deps_preload(versions.pkg, metadata) {
	if metadata != nil {
		metadata = dict((k, metadata.get(k, ''))
		for k
			in
		f._portdb_keys)
	}
	f._apply_dynamic_deps(versions.pkg, metadata)
	f._aux_get_history.add(versions.pkg.cpv)
}

func(f*FakeVartree) cpv_discard(versions.pkg) {
	old_pkg := f.dbapi.get(versions.pkg)
	if old_pkg != nil {
		f.dbapi.cpv_remove(old_pkg)
		f._pkg_cache.pop(old_pkg, None)
		f._aux_get_history.discard(old_pkg.cpv)
	}
}

// 1
func(f*FakeVartree) sync(acquire_lock int) {
	locked := false
//try:
	if acquire_lock && myutil.osAccess(f._real_vardb._dbroot, os.O_RDONLY) {
		f._real_vardb.lock()
		locked = true
	}
	f._sync()
//finally:
	if locked {
		f._real_vardb.unlock()
	}

//try:
	f.dbapi.aux_get = f._aux_get
	f.settings._populate_treeVirtuals_if_needed(f)
//finally:
	if f._dynamic_deps {
		f.dbapi.aux_get = f._aux_get_wrapper
	}
}

func(f*FakeVartree) _sync() {

	real_vardb := f._root_config.trees["vartree"].dbapi
	current_cpv_set := frozenset(real_vardb.cpv_all())
	pkg_vardb := f.dbapi

	for versions.pkg
		in
	list(pkg_vardb) {
		if versions.pkg.cpv not
		in
		current_cpv_set{
			f.cpv_discard(versions.pkg)
		}
	}

	slot_counters :=
	{
	}
	root_config := f._pkg_root_config
	validation_keys := []string{"COUNTER", "_mtime_"}
	for cpv := range current_cpv_set {

		pkg_hash_key := &structs.Package{}._gen_hash_key(cpv = cpv,
			installed = true, root_config = root_config,
			type_name = "installed")
		versions.pkg = pkg_vardb.get(pkg_hash_key)
		if versions.pkg != nil {
			counter, mtime = real_vardb.aux_get(cpv, validation_keys)
		try:
			counter = long(counter)
			except
		ValueError:
			counter = 0

			if counter != versions.pkg.counter || mtime != versions.pkg.mtime {
				f.cpv_discard(versions.pkg)
				versions.pkg = nil
			}
		}

		if versions.pkg == nil {
			versions.pkg = f._pkg(cpv)
		}

		other_counter := slot_counters.get(versions.pkg.slot_atom)
		if other_counter != nil {
			if other_counter > versions.pkg.counter {
				continue
			}
		}

		slot_counters[versions.pkg.slot_atom] = versions.pkg.counter
		pkg_vardb.cpv_inject(versions.pkg)
	}

	real_vardb.flush_cache()
}

func(f*FakeVartree) _pkg(cpv *versions.PkgStr) *structs.Package {
	pkg := structs.NewPackage(true,  cpv, true,
		zip(f._db_keys, f._real_vardb.aux_get(cpv, f._db_keys)),
		f._pkg_root_config, "installed")

	f._pkg_cache[pkg] = pkg
	return pkg
}

func grab_global_updates(portdb *dbapi.portdbapi) map[string][][]string{
	retupdates := map[string][][]string{}

	for _, repo_name := range portdb.getRepositories("") {
		repo := portdb.getRepositoryPath(repo_name)
		updpath := filepath.Join(repo, "profiles", "updates")
		if !myutil.pathIsDir(updpath) {
			continue
		}

		//try:
		rawupdates := atom.grab_updates(updpath, nil)
		//except portage.exception.DirectoryNotFound:
		//rawupdates = []
		upd_commands := [][]string{}
		for _, v := range rawupdates {
			mycontent := v.c
			commands, _ := atom.parse_updates(mycontent)
			upd_commands = append(upd_commands, commands...)
		}
		retupdates[repo_name] = upd_commands
	}

	master_repo := portdb.repositories.mainRepo()
	if _, ok := retupdates[master_repo.Name]; ok {
		retupdates["DEFAULT"] = retupdates[master_repo.Name]
	}

	return retupdates
}

func perform_global_updates(mycpv string, aux_dict map[string]string, mydb dbapi.IDbApi, myupdates map[string][][]string) {

	//try:
	pkg := versions.NewPkgStr(mycpv, aux_dict, mydb.settings, "", "", "", 0, 0, "", 0, nil)
	//except InvalidData:
	//return
	aux_dict2 := map[string]string{}
	for _, k := range structs.NewPackage().depKeys {
		aux_dict2[k] = aux_dict[k]
	}
	aux_dict = aux_dict2
	mycommands, ok := myupdates[pkg.repo]
	if !ok {
		//except KeyError:
		mycommands, ok = myupdates["DEFAULT"]
		if !ok {
			//except KeyError:
			return
		}
	}

	if len(mycommands) == 0 {
		return
	}

	updates := atom.update_dbentries(mycommands, aux_dict, "", pkg)
	if len(updates) > 0 {
		mydb.aux_update(mycpv, updates)
	}
}

type FifoIpcDaemon struct {
	*AbstractPollTask

	_files *struct{pipe_in int}
	input_fifo, output_fifo string
}

func (f *FifoIpcDaemon) _start() {
	f._files = &struct{ pipe_in int }{}

	f._files.pipe_in, _ = syscall.Open(f.input_fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0644)

	f.scheduler.add_reader(f._files.pipe_in, f._input_handler)

	f._registered = true
}

func (f *FifoIpcDaemon) _reopen_input() {
	f.scheduler.remove_reader(f._files.pipe_in)
	syscall.Close(f._files.pipe_in)
	f._files.pipe_in, _ =
		syscall.Open(f.input_fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0644)

	f.scheduler.add_reader(f._files.pipe_in, f._input_handler)
}

func (f *FifoIpcDaemon) _cancel() {
	if f.returncode == nil {
		i := 1
		f.returncode = &i
	}
	f._unregister()
	f._async_wait()
}

func (f *FifoIpcDaemon) _input_handler() bool {
	//raise NotImplementedError(f)
	 return true
}

func (f *FifoIpcDaemon) _unregister() {

	f._registered = false

	if f._files != nil {
		for f1
			in
		f._files.values() {
			f.scheduler.remove_reader(f1)
			syscall.Close(f1)
		}
		f._files = nil
	}
}

func NewFifoIpcDaemon()*FifoIpcDaemon {
	f := &FifoIpcDaemon{}
	f.AbstractPollTask = NewAbstractPollTask()

	return f
}

type JobStatusDisplay struct {
	_bound_properties                      []string
	_min_display_latency                   int
	_default_term_codes, _termcap_name_map map[string]string

	quiet, xterm_titles, _changed, _displayed, _isatty bool
	maxval, merges, width, _jobs_column_width          int
	_last_display_time                                 int64
	_term_codes                                        map[string]string

	curval,failed,running int
}

// false, true
func NewJobStatusDisplay(quiet, xterm_titles bool)*JobStatusDisplay {
	j := &JobStatusDisplay{}

	j._bound_properties = []string{"curval", "failed", "running"}

	j._min_display_latency = 2

	j._default_term_codes = map[string]string {
		"cr"  : "\r",
			"el"  : "\x1b[K",
			"nel" : "\n",
	}

	j._termcap_name_map = map[string]string{
		"carriage_return" : "cr",
			"clr_eol"         : "el",
			"newline"         : "nel",
	}


	j.quiet=quiet
	j.xterm_titles=xterm_titles
	j.maxval=0
	j.merges=0
	j._changed=false
	j._displayed=false
	j._last_display_time=int64(0)

	j.reset()

	isatty := os.Getenv("TERM") != "dumb" &&terminal.IsTerminal(syscall.Stdout)
	j._isatty=isatty
	if ! isatty || ! j._init_term() {
		term_codes :=map[string]string{}
		for k, capname:= range j._termcap_name_map {
			term_codes[k] = j._default_term_codes[capname]
		}
		j._term_codes = term_codes
	}

	width := 80
	if j._isatty {
		_, width, _ = output.get_term_size(0)
	}
	j._set_width(width)
	return j
}

func(j*JobStatusDisplay) _set_width( width int) {
	if width == j.width {
		return
	}
	if width <= 0 || width > 80 {
		width = 80
	}
	j.width = width
	j._jobs_column_width = width-32
}

func(j*JobStatusDisplay) _write(s string) {
	out := os.Stdout
	out.Write([]byte(s))
	out.Sync()
}

func(j*JobStatusDisplay) _init_term() bool {

	term_type := strings.TrimSpace(os.Getenv("TERM"))
	if  term_type== "" {
		return false
	}
	tigetstr = None

try:
	import curses

try:
	curses.setupterm(term_type, j.out.fileno())
	tigetstr = curses.tigetstr
	except
	curses.error:
	pass
	except
ImportError:
	pass

	if tigetstr is
None:
	return false

	term_codes =
	{
	}
	for k, capname
	in
	j._termcap_name_map.items():
	code = tigetstr(portage._native_string(capname))
	if code is
None:
	code = j._default_term_codes[capname]
	term_codes[k] = code
	object.__setattr__(j, "_term_codes", term_codes)
	return true
}

func(j*JobStatusDisplay) _format_msg( msg string)string {
	return fmt.Sprintf(">>> %s" , msg)
}

func(j*JobStatusDisplay) _erase() {
	j._write(j._term_codes["carriage_return"] + j._term_codes["clr_eol"])
	j._displayed = false
}

func(j*JobStatusDisplay) _display( line string) {
	j._write(line)
	j._displayed = true
}

func(j*JobStatusDisplay) _update( msg string) {

	if ! j._isatty {
		j._write(j._format_msg(msg) + j._term_codes["newline"])
		j._displayed = true
		return
	}

	if j._displayed {
		j._erase()
	}

	j._display(j._format_msg(msg))
}

func(j*JobStatusDisplay) displayMessage(msg string) {

	was_displayed := j._displayed

	if j._isatty && j._displayed {
		j._erase()
	}

	j._write(j._format_msg(msg) + j._term_codes["newline"])
	j._displayed = false

	if was_displayed {
		j._changed = true
		j.display()
	}
}

func(j*JobStatusDisplay) reset() {
	j.maxval = 0
	j.merges = 0

	j.curval = 0
	j.failed = 0
	j.running = 0

	if j._displayed {
		j._write(j._term_codes["newline"])
		j._displayed = false
	}
}

func(j*JobStatusDisplay) setCurval(curval int) {
	if j.curval!= curval{
		j.curval=curval
		j._property_change()
	}
}


func(j*JobStatusDisplay) setFailed(failed int) {
	if j.failed!= failed{
		j.failed=failed
		j._property_change()
	}
}

func(j*JobStatusDisplay) setRunning(running int) {
	if j.running!= running{
		j.running=running
		j._property_change()
	}
}

func(j*JobStatusDisplay) _property_change() {
	j._changed = true
	j.display()
}

func(j*JobStatusDisplay) _load_avg_str()string {
	avg1, avg2, avg3, err := getloadavg()
	if err != nil {
		//except OSError:
		return "unknown"
	}

	max_avg := math.Max(math.Max(avg1, avg2), avg3)

	digits := 0
	if max_avg < 10 {
		digits = 2
	} else if max_avg < 100 {
		digits = 1
	}

	return fmt.Sprintf("%."+fmt.Sprint(digits)+"f", avg1) + ", " +
		fmt.Sprintf("%."+fmt.Sprint(digits)+"f", avg2) + ", " +
		fmt.Sprintf("%."+fmt.Sprint(digits)+"f", avg3)
}

func(j*JobStatusDisplay) display() bool {

	if j.quiet {
		return true
	}
	current_time := time.Now().Unix()
	time_delta := current_time - j._last_display_time
	if j._displayed && !j._changed {
		if !j._isatty {
			return true
		}
		if int(time_delta) < j._min_display_latency {
			return true
		}
	}

	j._last_display_time = current_time
	j._changed = false
	j._display_status()
	return true
}

func(j*JobStatusDisplay) _display_status() {
	curval_str := fmt.Sprintf("%s", j.curval, )
	maxval_str := fmt.Sprintf("%s", j.maxval, )
	running_str := fmt.Sprintf("%s", j.running, )
	failed_str := fmt.Sprintf("%s", j.failed, )
	load_avg_str := j._load_avg_str()

	color_output := &bytes.Buffer{}
	plain_output := &bytes.Buffer{}
	style_file := output.NewConsoleStylefile(color_output)
	style_file.write_listener = plain_output
	style_writer := &output.StyleWriter{File: style_file, maxcol: 9999}
	style_writer.style_listener = style_file.new_styles
	f := &output.AbstractFormatter{Writer: style_writer}

	number_style := "INFORM"
	f.add_literal_data("Jobs: ")
	f.push_style(number_style)
	f.add_literal_data(curval_str)
	f.pop_style()
	f.add_literal_data(" of ")
	f.push_style(number_style)
	f.add_literal_data(maxval_str)
	f.pop_style()
	f.add_literal_data(" complete")

	if j.running != 0 {
		f.add_literal_data(", ")
		f.push_style(number_style)
		f.add_literal_data(running_str)
		f.pop_style()
		f.add_literal_data(" running")
	}

	if j.failed != 0 {
		f.add_literal_data(", ")
		f.push_style(number_style)
		f.add_literal_data(failed_str)
		f.pop_style()
		f.add_literal_data(" failed")
	}

	padding := j._jobs_column_width - len(plain_output.String())
	if padding > 0 {
		f.add_literal_data(strings.Repeat(" ", padding))
	}

	f.add_literal_data("Load avg: ")
	f.add_literal_data(load_avg_str)

	plain_outputS := plain_output.String()
	if j._isatty && len(plain_outputS) > j.width {
		j._update(plain_outputS[:j.width])
	} else {
		j._update(color_output.String())
	}

	if j.xterm_titles {
		title_str := strings.Join(strings.Fields(plain_outputS), " ")
		hostname := os.Getenv("HOSTNAME")
		if hostname != "" {
			title_str = fmt.Sprintf("%s: %s", hostname, title_str)
		}
		output.XtermTitle(title_str, false)
	}
}

type MergeListItem struct {
	*CompositeTask

	//slots
	_install_task *EbuildBuild
	args_set      *sets.InternalPackageSet
	binpkg_opts   *_binpkg_opts_class
	build_opts    *_build_opts_class
	config_pool   *_ConfigPool
	logger        *_emerge_log_class
	pkg_count     *_pkg_count_class
	settings      *config.Config
	statusMessage func(string)
	world_atom    func()
	emerge_opts, find_blockers, mtimedb, pkg,
	pkg_to_replace, prefetcher
}

func(m *MergeListItem) _start() {

	pkg := m.pkg
	build_opts := m.build_opts

	if pkg.installed {
		i := 0
		m.returncode = &i
		m._async_wait()
		return
	}

	args_set := m.args_set
	find_blockers := m.find_blockers
	logger := m.logger
	mtimedb := m.mtimedb
	pkg_count := m.pkg_count
	scheduler := m.scheduler
	settings := m.settings
	world_atom := m.world_atom
	ldpath_mtimes := mtimedb["ldpath"]

	action_desc := "Emerging"
	preposition := "for"
	pkg_color := "PKG_MERGE"
	if pkg.type_name == "binary" {
		pkg_color = "PKG_BINARY_MERGE"
		action_desc += " binary"
	}

	if build_opts.fetchonly {
		action_desc = "Fetching"
	}

	msg := fmt.Sprintf("%s (%s of %s) %s",
		action_desc,
		output.colorize("MERGE_LIST_PROGRESS", str(pkg_count.curval)),
		output.colorize("MERGE_LIST_PROGRESS", str(pkg_count.maxval)),
		output.colorize(pkg_color, pkg.cpv+dep.repoSeparator+pkg.repo))

	if pkg.root_config.settings["ROOT"] != "/" {
		msg += fmt.Sprintf(" %s %s", preposition, pkg.root)
	}

	if build_opts.pretend == "" {
		m.statusMessage(msg)
		logger.log(fmt.Sprintf(" >>> emerge (%s of %s) %s to %s",
			pkg_count.curval, pkg_count.maxval, pkg.cpv, pkg.root))
	}

	if pkg.type_name == "ebuild" {

		build := NewEbuildBuild(args_set, m.background, m.config_pool,
			find_blockers, ldpath_mtimes, logger, build_opts, pkg,
			pkg_count, m.prefetcher, scheduler, settings, world_atom)

		m._install_task = build
		m._start_task(build, m._default_final_exit)
		return
	} else if pkg.type_name == "binary" {

		binpkg := NewBinpkg(m.background, find_blockers,
			ldpath_mtimes, logger, m.binpkg_opts, pkg, pkg_count,
			m.prefetcher, settings, scheduler, world_atom)

		m._install_task = binpkg
		m._start_task(binpkg, m._default_final_exit)
		return
	}
}

func(m *MergeListItem) create_install_task() {

	pkg := m.pkg
	build_opts := m.build_opts
	mtimedb := m.mtimedb
	scheduler := m.scheduler
	settings := m.settings
	world_atom := m.world_atom
	ldpath_mtimes := mtimedb["ldpath"]

	if pkg.installed {
		if !(build_opts.buildpkgonly || build_opts.fetchonly || build_opts.pretend) {

			task = NewPackageUninstall(m.background, ldpath_mtimes,
				m.emerge_opts, pkg, scheduler, settings, world_atom)
		}else {
			task = NewAsynchronousTask()
		}

	}else if  build_opts.fetchonly || build_opts.buildpkgonly {
		task = NewAsynchronousTask()
	}else {
		task = m._install_task.create_install_task()
	}

	return task
}

func NewMergeListItem(args_set *sets.InternalPackageSet, background bool,
	binpkg_opts *_binpkg_opts_class, build_opts *_build_opts_class,
	config_pool *_ConfigPool, emerge_opts , find_blockers ,
	logger *_emerge_log_class,
mtimedb , pkg, pkg_count *_pkg_count_class, pkg_to_replace,
prefetcher , scheduler *SchedulerInterface,
settings *config.Config, statusMessage func(string) , world_atom func() )*MergeListItem {
	m := &MergeListItem{}
	m.CompositeTask = NewCompositeTask()
	m.args_set = args_set
	m.background = background
	m.binpkg_opts = binpkg_opts
	m.build_opts = build_opts
	m.config_pool = config_pool
	m.emerge_opts = emerge_opts
	m.find_blockers = find_blockers
	m.logger = logger
	m.mtimedb = logger
	m.pkg = pkg
	m.pkg_count = pkg_count
	m.pkg_to_replace = pkg_to_replace
	m.prefetcher = prefetcher
	m.scheduler = scheduler
	m.settings = settings
	m.statusMessage = settings
	m.world_atom = world_atom
	return m
}

type MetadataRegen struct{
	*AsyncScheduler

	_portdb *dbapi.portdbapi
	_global_cleanse,_write_auxdb bool
	_cp_iter string
}

// "", nil, true
func NewMetadataRegen( portdb *dbapi.portdbapi, cp_iter string, consumer=None,
write_auxdb bool, /* **kwargs*/ max_jobs, max_load, main)*MetadataRegen {
	m := &MetadataRegen{}
	m.AsyncScheduler = NewAsyncScheduler(max_jobs, max_load, main)
	m._portdb = portdb
	m._write_auxdb = write_auxdb
	m._global_cleanse = false
	if cp_iter == "" {
		cp_iter = m._iter_every_cp()[0]
		m._global_cleanse = true
	}
	m._cp_iter = cp_iter
	m._consumer = consumer

	m._valid_pkgs = set()
	m._cp_set = set()
	m._process_iter = m._iter_metadata_processes()
	m._running_tasks = set()
	return m
}

func(m*MetadataRegen) _next_task() {
	return next(m._process_iter)
}

func(m*MetadataRegen) _iter_every_cp() []string {
	cp_all := m._portdb.cp_all
	cps := []string{}
	for _, category:= range myutil.Sorted(m._portdb.categories()) {
		for _, cp := range cp_all(map[string]bool{category:true}, nil, false, true) {
			cps = append(cps, cp)
		}
	}
	return cps
}

func(m*MetadataRegen) _iter_metadata_processes() {
	portdb := m._portdb
	valid_pkgs := m._valid_pkgs
	cp_set := m._cp_set
	consumer := m._consumer

	msg.WriteMsgStdout("Regenerating cache entries...\n", 0)
	for _, cp := range m._cp_iter {
		if m._terminated.is_set() {
			break
		}
		cp_set.add(cp)
		msg.WriteMsgStdout(fmt.Sprintf("Processing %s\n", cp), 0)
		for _, mytree := range portdb.porttrees {
			repo := portdb.repositories.GetRepoForLocation(mytree)
			cpv_list := portdb.cp_list(cp, 1, []string{repo.Location})
			for _, cpv := range cpv_list {
				if m._terminated.is_set() {
					break
				}
				valid_pkgs.add(cpv)
				ebuild_path, repo_path := portdb.findname2(cpv, "", repo.Name)
				if ebuild_path == "" {
					//raise AssertionError("ebuild not found for '%s%s%s'"%(cpv, _repo_separator, repo.name))
				}
				metadata, ebuild_hash := portdb._pull_valid_cache(cpv, ebuild_path, repo_path)
				if metadata != nil {
					if consumer != nil {
						consumer(cpv, repo_path, metadata, ebuild_hash, true)
					}
					continue
				}

				yield
				NewEbuildMetadataPhase(cpv, ebuild_hash, portdb, repo_path, nil, portdb.doebuild_settings,
					write_auxdb = m._write_auxdb)
			}
		}
	}
}

func(m*MetadataRegen) _cleanup() {
	m.AsyncScheduler._cleanup()

	portdb := m._portdb
	dead_nodes :=
	{
	}

	if m._terminated.is_set() {
		portdb.flush_cache()
		return
	}

	if m._global_cleanse {
		for _, mytree:= range portdb.porttrees {
		try:
			dead_nodes[mytree] = set(portdb.auxdb[mytree])
			except
			CacheError
			as
		e:
			msg.WriteMsg(fmt.Sprintf("Error listing cache entries for " +
			"'%s': %s, continuing...\n" ,mytree, e), -1, nil)
			del
			e
			dead_nodes = nil
			break
		}
	}else {
		cp_set = m._cp_set
		cpv_getkey = portage.cpv_getkey
		for mytree
			in
		portdb.porttrees:
	try:
		dead_nodes[mytree] = set(versions.cpv
		for versions.cpv
		in \
		portdb.auxdb[mytree] \
		if cpv_getkey(versions.cpv) in
		cp_set)
		except
		CacheError
		as
	e:
		msg.WriteMsg(fmt.Sprintf("Error listing cache entries for "+
			"'%s': %s, continuing...\n", mytree, e), -1, nil)
		del
		e
		dead_nodes = None
		break
	}

	if dead_nodes {
		for y
			in
		m._valid_pkgs {
			for _, mytree := range portdb.porttrees {
				if s, _ := portdb.findname2(y, mytree, ""); s != "" {
					dead_nodes[mytree].discard(y)
				}
			}
		}

		for mytree, nodes
			in
		dead_nodes.items() {
			auxdb = portdb.auxdb[mytree]
			for y
				in
			nodes {
			try:
				del
				auxdb[y]
				except(KeyError, CacheError):
				pass
			}
		}
	}

	portdb.flush_cache()
}

func(m*MetadataRegen) _task_exit(metadata_process) {

	if metadata_process.returncode != 0 {
		m._valid_pkgs.discard(metadata_process.cpv)
		if not m._terminated_tasks {
			msg.WriteMsg(fmt.Sprintf("Error processing %s, continuing...\n", metadata_process.cpv, ), -1, nil)
		}
	}

	if m._consumer != nil {
		m._consumer(metadata_process.cpv,
			metadata_process.repo_path,
			metadata_process.metadata,
			metadata_process.ebuild_hash,
			metadata_process.eapi_supported)
	}

	m.AsyncScheduler._task_exit(metadata_process)
}

type MiscFunctionsProcess struct {
	*AbstractEbuildProcess
	commands []string
	ld_preload_sandbox
}

func (m *MiscFunctionsProcess)_start() {
	settings := m.settings
	portage_bin_path := settings.ValueDict["PORTAGE_BIN_PATH"]
	misc_sh_binary := filepath.Join(portage_bin_path,
		filepath.Base(_const.MISC_SH_BINARY))

	m.args = append([]string{vars.ShellQuote(misc_sh_binary)}, m.commands...)
	if m.logfile == "" &&m.settings.ValueDict["PORTAGE_BACKGROUND"] != "subprocess" {
		m.logfile = settings.ValueDict["PORTAGE_LOG_FILE"]
	}

	m.AbstractEbuildProcess._start()
}

func (m *MiscFunctionsProcess) _spawn(args []string, debug bool, free *bool, droppriv,
	sesandbox, fakeroot, networked, ipc, mountns, pidns bool, **keywords) {

	if free == nil {
		if m.ld_preload_sandbox == nil {
			*free = false
		} else {
			*free = not m.ld_preload_sandbox
		}
	}

	if m._dummy_pipe_fd != 0 {
		m.settings.ValueDict["PORTAGE_PIPE_FD"] = fmt.Sprint(m._dummy_pipe_fd)
	}

	if m.settings.Features.Features["fakeroot"]{
		fakeroot = true
	}

	phase_backup := m.settings.ValueDict["EBUILD_PHASE"]
	delete(m.settings.ValueDict, "EBUILD_PHASE")

	defer func() {
		if phase_backup != "" {
			m.settings.ValueDict["EBUILD_PHASE"] = phase_backup
		}
		delete(m.settings.ValueDict, "PORTAGE_PIPE_FD")
	}()
	return atom.spawnE(strings.Join(args, " "), m.settings, debug, *free, droppriv,
		sesandbox, fakeroot, networked, ipc, mountns, pidns, **keywords)
}

func NewMiscFunctionsProcess(background bool, commands []string, phase string, logfile string, fd_pipe map[int]int, scheduler *SchedulerInterface, settings *config.Config)*MiscFunctionsProcess {
	m := &MiscFunctionsProcess{}
	m.AbstractEbuildProcess = NewAbstractEbuildProcess(nil, background, fd_pipe, logfile, phase, scheduler, settings, )
	m.background = background
	m.commands = commands
	m.phase = phase
	m.logfile = logfile
	m.fd_pipes = fd_pipe
	m.scheduler = scheduler
	m.settings = settings
	return m
}

type iUse struct {
	__weakref__, _pkg                  string
	tokens                             []string
	iuseImplicitMatch                  func(string) bool
	aliasMapping                       map[string][]string
	all, allAliases, enabled, disabled map[string]bool
}

func (i *iUse) isValidFlag(flags []string) bool {
	for _, flag := range flags {
		if !i.all[flag] && !i.allAliases[flag] && !i.iuseImplicitMatch(flag) {
			return false
		}
	}
	return true
}

func (i *iUse) getMissingIuse(flags []string) []string {
	missingIUse := []string{}
	for _, flag := range flags {
		if !i.all[flag] && !i.allAliases[flag] && !i.iuseImplicitMatch(flag) {
			missingIUse = append(missingIUse, flag)
		}
	}
	return missingIUse
}

func (i *iUse) getRealFlag(flag string) string {
	if i.all[flag] {
		return flag
	} else if i.allAliases[flag] {
		for k, v := range i.aliasMapping {
			for _, x := range v {
				if flag == x {
					return k
				}
			}
		}
	}
	if i.iuseImplicitMatch(flag) {
		return flag
	}
	return ""
}

func NewIUse(pkg string, tokens []string, iuseImplicitMatch func(string) bool, aliases map[string][]string, eapi string) *iUse {
	i := &iUse{}
	i._pkg = pkg
	i.tokens = tokens
	i.iuseImplicitMatch = iuseImplicitMatch
	enabled := []string{}
	disabled := []string{}
	other := []string{}
	enabledAliases := []string{}
	disabledAliases := []string{}
	otherAliases := []string{}
	aliasesSupported := eapi2.eapiHasUseAliases(eapi)
	i.aliasMapping = map[string][]string{}
	for _, x := range tokens {
		prefix := x[:1]
		if prefix == "+" {
			enabled = append(enabled, x[1:])
			if aliasesSupported {
				if a, ok := aliases[x[1:]]; ok {
					i.aliasMapping[x[1:]] = a
				} else {
					i.aliasMapping[x[1:]] = []string{}
				}
				enabledAliases = append(enabledAliases, i.aliasMapping[x[1:]]...)
			}
		} else if prefix == "-" {
			disabled = append(disabled, x[1:])
			if aliasesSupported {
				if a, ok := aliases[x[1:]]; ok {
					i.aliasMapping[x[1:]] = a
				} else {
					i.aliasMapping[x[1:]] = []string{}
				}
				disabledAliases = append(disabledAliases, i.aliasMapping[x[1:]]...)
			}
		} else {
			other = append(other, x[1:])
			if aliasesSupported {
				if a, ok := aliases[x[1:]]; ok {
					i.aliasMapping[x[1:]] = a
				} else {
					i.aliasMapping[x[1:]] = []string{}
				}
				otherAliases = append(otherAliases, i.aliasMapping[x[1:]]...)
			}
		}
	}
	i.enabled = map[string]bool{}
	for _, x := range append(enabled, enabledAliases...) {
		i.enabled[x] = true
	}
	i.disabled = map[string]bool{}
	for _, x := range append(disabled, disabledAliases...) {
		i.disabled[x] = true
	}
	i.all = map[string]bool{}
	for _, x := range append(append(enabled, disabled...), other...) {
		i.enabled[x] = true
	}
	i.allAliases = map[string]bool{}
	for _, x := range append(append(enabledAliases, disabledAliases...), otherAliases...) {
		i.allAliases[x] = true
	}

	return i
}

type PackageMerge struct{
	*CompositeTask

	// slot
	dbapi.merge, postinst_failure
}

func (p *PackageMerge) _start() {

	p.scheduler = p.merge.scheduler
	pkg := p.merge.pkg
	pkg_count := p.merge.pkg_count
	pkg_color := "PKG_MERGE"
	if pkg.type_name == "binary" {
		pkg_color = "PKG_BINARY_MERGE"
	}

	if pkg.installed {
		action_desc = "Uninstalling"
		preposition = "from"
		counter_str = ""
	} else {
		action_desc = "Installing"
		preposition = "to"
		counter_str = fmt.Sprintf("(%s of %s) ",
			output.colorize("MERGE_LIST_PROGRESS", str(pkg_count.curval)),
			output.colorize("MERGE_LIST_PROGRESS", str(pkg_count.maxval)))
	}

	msg := fmt.Sprintf("%s %s%s", action_desc, counter_str,
		output.colorize(pkg_color, pkg.cpv+dep.repoSeparator+pkg.repo))

	if pkg.root_config.settings["ROOT"] != "/" {
		msg += fmt.Sprintf(" %s %s", preposition, pkg.root)
	}

	if !p.merge.build_opts.fetchonly && !
		p.merge.build_opts.pretend && !
		p.merge.build_opts.buildpkgonly {
		p.merge.statusMessage(msg)
	}

	task := p.merge.create_install_task()
	p._start_task(task, p._install_exit)
}

func (p *PackageMerge) _install_exit( task) {
	p.postinst_failure = task.postinst_failure
	p._final_exit(task)
	p.wait()
}

func NewPackageMerge(merge , scheduler *SchedulerInterface) *PackageMerge {
	p := &PackageMerge{}
	p.CompositeTask = NewCompositeTask()
	p.merge = merge
	p.scheduler = scheduler
	return p
}

type PackagePhase struct {
	*CompositeTask

	_shell_binary string

	// slots
	_pkg_install_mask *bad2.InstallMask
	settings          *config.Config
	fd_pipes        map[int]int
	actionmap       ebuild2.Actionmap
	logfile, _proot string
}

func(p*PackagePhase) _start() {
	f, err := ioutil.ReadFile(filepath.Join(p.settings.ValueDict["PORTAGE_BUILDDIR"],
		"build-info", "PKG_INSTALL_MASK"))
	if err != nil {
		p._pkg_install_mask = nil
	} else {
		p._pkg_install_mask = bad2.NewInstallMask(string(f))
	}
	if p._pkg_install_mask != nil {
		p._proot = filepath.Join(p.settings.ValueDict["T"], "packaging")
		p._start_task(NewSpawnProcess(
			[]string{p._shell_binary, "-e", "-c", fmt.Sprintf("rm -rf {PROOT}; "+
			"cp -pPR $(cp --help | grep -q -- \" ^ [[: space:]]*-l, \" && echo -l)"+
			" \"${{D}}\" {%s}",  vars.ShellQuote(p._proot))},
			 p.background, p.settings.environ(), nil,
			 p.scheduler,  p.logfile),
		p._copy_proot_exit)
	} else {
		p._proot = p.settings.ValueDict["D"]
		p._start_package_phase()
	}
}

func(p*PackagePhase) _copy_proot_exit( proc) {
	if p._default_exit(proc) != 0 {
		p.wait()
	}else {
		p._start_task(NewAsyncFunction(
			util.install_mask_dir,
			 (filepath.Join(p._proot,
			strings.TrimLeft(p.settings.ValueDict["EPREFIX"],string(filepath.Separator))),
			p._pkg_install_mask)),
		p._pkg_install_mask_exit)
	}
}

func(p*PackagePhase) _pkg_install_mask_exit( proc) {
	if p._default_exit(proc) != 0 {
		p.wait()
	}else {
		p._start_package_phase()
	}
}

func(p*PackagePhase) _start_package_phase() {
	ebuild_process := NewEbuildProcess( p.actionmap, p.background, p.fd_pipes,
		 p.logfile,"package", p.scheduler, p.settings)

	if p._pkg_install_mask != nil {
		d_orig := p.settings.ValueDict["D"]
	//try:
		p.settings.ValueDict["D"] = p._proot
		p._start_task(ebuild_process, p._pkg_install_mask_cleanup)
	//finally:
		p.settings.ValueDict["D"] = d_orig
	}else {
		p._start_task(ebuild_process, p._default_final_exit)
	}
}

func(p*PackagePhase) _pkg_install_mask_cleanup( proc) {
	if p._default_exit(proc) != 0 {
		p.wait()
	} else {
		p._start_task(NewSpawnProcess([]string{"rm", "-rf", p._proot},
			p.background, p.settings.environ(), nil, p.scheduler, p.logfile),
			p._default_final_exit)
	}
}

func NewPackagePhase(actionmap ebuild2.Actionmap, background bool, fd_pipes map[int]int,
	logfile string, scheduler *SchedulerInterface, settings *config.Config)*PackagePhase {
	p := &PackagePhase{}
	p.CompositeTask = NewCompositeTask()
	p._shell_binary = _const.BashBinary

	p.actionmap = actionmap
	p.background = background
	p.fd_pipes = fd_pipes
	p.logfile = logfile
	p.scheduler = scheduler
	p.settings = settings

	return p
}

type PackageUninstall struct{
	*CompositeTask

	// slot
	settings *config.Config
	pkg *versions.PkgStr
	_builddir_lock *EbuildBuildDir
	world_atom
	ldpath_mtimes
	opts
}

func(p*PackageUninstall) _start() {

	vardb := p.pkg.root_config.trees["vartree"].dbapi
	dbdir := vardb.getpath(p.pkg.cpv)
	if !myutil.PathExists(dbdir) {
		i := 0
		p.returncode = &i
		p._async_wait()
		return
	}

	p.settings.SetCpv(p.pkg, nil)
	cat, pf := versions.catsplit(p.pkg.cpv.string)[0], versions.catsplit(p.pkg.cpv.string)[1]
	myebuildpath := filepath.Join(dbdir, pf+".ebuild")

	//try:
	atom.doebuild_environment(myebuildpath, "prerm",
		nil, p.settings, false, nil, vardb)
	//except UnsupportedAPIException:
	//pass

	p._builddir_lock = NewEbuildBuildDir(p.scheduler, p.settings)
	p._start_task(NewAsyncTaskFuture(p._builddir_lock.async_lock()), p._start_unmerge)
}

func(p*PackageUninstall) _start_unmerge( lock_task) {
	p._assert_current(lock_task)
	if lock_task.cancelled {
		p._default_final_exit(lock_task)
		return
	}

	lock_task.future.result()
	atom.Prepare_build_dirs(p.settings, true)

	retval, pkgmap := _unmerge_display(p.pkg.root_config,
		p.opts, "unmerge", [p.pkg.cpv], clean_delay = 0,
		writemsg_level = p._writemsg_level)

	if retval != 0 {
		p._async_unlock_builddir(retval)
		return
	}

	p._writemsg_level(fmt.Sprintf(">>> Unmerging %s...\n" ,p.pkg.cpv, ), -1, 0)
	p._emergelog(fmt.Sprintf("=== Unmerging... (%s)" ,p.pkg.cpv, ))

	cat, pf := versions.catsplit(p.pkg.cpv.string)[0], versions.catsplit(p.pkg.cpv.string)[1]
	unmerge_task := NewMergeProcess(
		cat, pf, p.settings, "vartree", p.pkg.root_config.trees["vartree"],
		 p.scheduler, p.background, nil, "","","",
		p.pkg.root_config.trees["vartree"].dbapi,
		p.ldpath_mtimes, p.settings.get("PORTAGE_LOG_FILE"), nil, dbapi.unmerge =true)

	p._start_task(unmerge_task, p._unmerge_exit)
}

func(p*PackageUninstall) _unmerge_exit( unmerge_task) {
	if p._final_exit(unmerge_task) != 0 {
		p._emergelog(fmt.Sprintf(" !!! unmerge FAILURE: %s", p.pkg.cpv, ))
	} else {
		p._emergelog(fmt.Sprintf(" >>> unmerge success: %s", p.pkg.cpv, ))
		p.world_atom(p.pkg)
	}
	p._async_unlock_builddir(p.returncode)
}

// nil
func(p *PackageUninstall) _async_unlock_builddir(returncode *int) {
	if returncode != nil {
		p.returncode = nil
	}
	p._start_task(
		NewAsyncTaskFuture(p._builddir_lock.async_unlock()),
		func(t *int){p._unlock_builddir_exit(t, returncode)})
}

// nil
func(p*PackageUninstall) _unlock_builddir_exit(unlock_task, returncode *int) {
	p._assert_current(unlock_task)
	if unlock_task.cancelled && returncode!= nil {
		p._default_final_exit(unlock_task)
		return
	}

	//unlock_task.future.cancelled() || unlock_task.future.result()
	if returncode != nil {
		p.returncode = returncode
		p._async_wait()
	}
}

func(p*PackageUninstall) _emergelog( msg string) {
	atom.emergelog(!p.settings.Features.Features["notitles"], msg, "")
}

// 0, 0
func(p*PackageUninstall) _writemsg_level(msg string, level, noiselevel int) {

	log_path := p.settings.ValueDict["PORTAGE_LOG_FILE"]
	background := p.background

	if log_path == "" {
		if !(background && level < 30) {
			msg.WriteMsgLevel(msg, level, noiselevel)
		}
	}else {
		p.scheduler.output(msg, log_path,false, level, noiselevel)
	}
}

func NewPackageUninstall(background bool, ldpath_mtimes = ldpath_mtimes, opts=m.emerge_opts,
	pkg *versions.PkgStr, scheduler *SchedulerInterface, settings *config.Config, world_atom=world_atom)*PackageUninstall {
	p := &PackageUninstall{}
	p.CompositeTask = NewCompositeTask()
	p.background = background
	p.ldpath_mtimes=ldpath_mtimes
	p.opts = opts
	p.pkg=pkg
	p.scheduler=scheduler
	p.settings=settings
	p.world_atom=world_atom
	return p
}

type PackageVirtualDbapi struct{
	*dbapi.dbapi
}

func NewPackageVirtualDbapi(settings) *PackageVirtualDbapi {
	p := &PackageVirtualDbapi{}
	p.dbapi = dbapi.NewDbapi()
	p.settings = settings
	p._match_cache =
	{
	}
	p._cp_map =
	{
	}
	p._cpv_map =
	{
	}
	return p
}

func(p*PackageVirtualDbapi) clear() {
	if len(p._cpv_map) > 0 {
		p._clear_cache()
		p._cp_map.clear()
		p._cpv_map.clear()
	}
}

func(p*PackageVirtualDbapi) copy() {
	obj := NewPackageVirtualDbapi(p.settings)
	obj._match_cache = p._match_cache.copy()
	obj._cp_map = p._cp_map.copy()
	for k, versions.v
	in
	obj._cp_map.items() {
		obj._cp_map[k] = versions.v[:]
	}
	obj._cpv_map = p._cpv_map.copy()
	return obj
}

func(p*PackageVirtualDbapi) __bool__() {
	return bool(p._cpv_map)
}

func(p*PackageVirtualDbapi) __iter__() {
	return iter(p._cpv_map.values())
}

func(p*PackageVirtualDbapi) __contains__( item) bool {
	existing = p._cpv_map.get(item.cpv)
	if existing != nil && existing == item {
		return true
	}
	return false
}

// nil
func(p*PackageVirtualDbapi) get( item, default1=None) {
	versions.cpv = getattr(item, "cpv", None)
	if versions.cpv == nil {
		if len(item) != 5 {
			return default1
		}
	}
	type_name, root, versions.cpv, operation, repo_key = item

	existing := p._cpv_map.get(versions.cpv)
	if existing != nil &&
		existing == item {
		return existing
	}
	return default1
}

func(p*PackageVirtualDbapi) match_pkgs( atom) {
	return [p._cpv_map[cpv]
	for cpv
	in
	p.match(atom)]
}

func(p*PackageVirtualDbapi) _clear_cache() {
	if p._categories != nil {
		p._categories = nil
	}
	if len(p._match_cache) > 0 {
		p._match_cache =
		{
		}
	}
}

// 1
func(p*PackageVirtualDbapi) match( origdep *dep.Atom, use_cache int) {
	atom := dbapi.dep_expand(origdep, p, 1, p.settings)
	cache_key := [2]*dep.Atom{atom, atom.unevaluatedAtom}
	result := p._match_cache[cache_key]
	if result != nil {
		return result[:]
	}
	result = list(p._iter_match(atom, p.cp_list(atom.cp, 1)))
	p._match_cache[cache_key] = result
	return result[:]
}

// nil
func(p*PackageVirtualDbapi) cpv_exists(versions.cpv, myrepo=None) int {
	return versions.cpv
	in
	p._cpv_map
}

// 1
func(p*PackageVirtualDbapi) cp_list( mycp string, use_cache int) {
	cache_key := (mycp, mycp)
	cachelist := p._match_cache.get(cache_key)
	if cachelist != nil {
		return cachelist[:]
	}
	cpv_list := p._cp_map.get(mycp)
	if cpv_list == nil {
		cpv_list = []string{}
	} else {
		cpv_list = []string{}
		for versions.pkg
			in
		cpv_list {
			cpv_list = append(versions.pkg.cpv)
		}
	}
	p._cpv_sort_ascending(cpv_list)
	p._match_cache[cache_key] = cpv_list
	return cpv_list[:]
}

// false
func(p*PackageVirtualDbapi) cp_all( sort bool) {
	if sort {
		return myutil.Sorted(p._cp_map)
	}else {
		return list(p._cp_map)
	}
}

func(p*PackageVirtualDbapi) cpv_all() {
	return list(p._cpv_map)
}

func(p*PackageVirtualDbapi) cpv_inject(versions.pkg) {
	cp_list := p._cp_map.get(versions.pkg.cp)
	if cp_list == nil {
		cp_list = []string{}
		p._cp_map[versions.pkg.cp] = cp_list
	}
	e_pkg := p._cpv_map.get(versions.pkg.cpv)
	if e_pkg != nil {
		if e_pkg == versions.pkg {
			return
		}
	}
	p.cpv_remove(e_pkg)
	for e_pkg
		in
	cp_list {
		if e_pkg.slot_atom == versions.pkg.slot_atom {
			if e_pkg == versions.pkg {
				return
			}
			p.cpv_remove(e_pkg)
			break
		}
	}
	cp_list = append(cp_list, versions.pkg)
	p._cpv_map[versions.pkg.cpv] = versions.pkg
	p._clear_cache()
}

func(p*PackageVirtualDbapi) cpv_remove(versions.pkg) {
	old_pkg := p._cpv_map.get(versions.pkg.cpv)
	if old_pkg != versions.pkg {
		raise
		KeyError(versions.pkg)
	}
	p._cp_map[versions.pkg.cp].remove(versions.pkg)
	del
	p._cpv_map[versions.pkg.cpv]
	p._clear_cache()
}

// nil
func(p*PackageVirtualDbapi) aux_get(versions.cpv, wants, myrepo=None) {
	metadata := p._cpv_map[versions.cpv]._metadata
	return [metadata.get(x, "")
	for x
	in
	wants]
}

func(p*PackageVirtualDbapi) aux_update(versions.cpv, values) {
	p._cpv_map[versions.cpv]._metadata.update(values)
	p._clear_cache()
}

type PipeReader struct {
	*AbstractPollTask

	// slot
	input_files map[string]int
	_read_data []string
	_use_array
}

func (p*PipeReader) _start() {
	p._read_data = []string{}

	for _, f := range p.input_files {
		fd := uintptr(f)
		//if isinstance(f, int)
		//else
		//f.fileno()
		ff, _ := unix.FcntlInt(fd, unix.F_GETFL, 0)
		unix.FcntlInt(fd, unix.F_SETFL,
			ff|unix.O_NONBLOCK)

		if p._use_array {
			p.scheduler.add_reader(f, func() bool {
				return p._array_output_handler(f)
			})
		} else {
			p.scheduler.add_reader(f, func() bool {
				return p._output_handler(f)
			})
		}
	}

	p._registered = true
}

func (p*PipeReader) _cancel() {
	p._unregister()
	if p.returncode == nil {
		p.returncode = &p._cancelled_returncode
	}
}

func (p*PipeReader) getvalue() string {
	return strings.Join(p._read_data, "")
}

func (p*PipeReader) close() {
	p._read_data = nil
}

func (p*PipeReader) _output_handler( fd int)bool {
	for {
		data := p._read_buf(fd)
		if data == nil {
			break
		}
		if len(data) > 0 {
			p._read_data = append(p._read_data, string(data))
		} else {
			p._unregister()
			//p.returncode = p.returncode ||0
			p._async_wait()
			break
		}
	}
	return true // add
}

func (p*PipeReader) _array_output_handler( f int) bool {
	for {
		data := p._read_array(f)
		if data == "" {
			break
		}
		if len(data) > 0 {
			p._read_data = append(p._read_data, data)
		} else {
			p._unregister()
			//p.returncode = p.returncode ||0
			p._async_wait()
			break
		}
	}

	return true
}

func (p*PipeReader) _unregister() {
	p._registered = false
	if p.input_files != nil {
		for _, f := range p.input_files {
			//if isinstance(f, int):
			p.scheduler.remove_reader(f)
			syscall.Close(f)
			//else:
			//p.scheduler.remove_reader(f.fileno())
			//f.close()
		}
		p.input_files = nil
	}
}

func NewPipeReader(input_files map[string]int, scheduler *SchedulerInterface)*PipeReader {
	p := &PipeReader{}
	p.AbstractPollTask = NewAbstractPollTask()

	p.input_files = input_files
	p.scheduler = scheduler

	return p
}


type SequentialTaskQueue struct{
	max_jobs int
	_scheduling bool
	running_tasks, _task_queue
}

func NewSequentialTaskQueue(**kwargs)*SequentialTaskQueue {
	s := &SequentialTaskQueue{}
	SlotObject.__init__(s, **kwargs)
	s._task_queue = deque()
	s.running_tasks = set()
	if s.max_jobs == 0 {
		s.max_jobs = 1
	}
	return s
}

func(s*SequentialTaskQueue) add( task) {
	s._task_queue.append(task)
	s.schedule()
}

func(s*SequentialTaskQueue) addFront(task) {
	s._task_queue.appendleft(task)
	s.schedule()
}

func(s*SequentialTaskQueue) schedule() {

	if s._scheduling {
		return
	}

	s._scheduling = true
try:
	while
	s._task_queue
	and(s.max_jobs
	is
	true
	or
	len(s.running_tasks) < s.max_jobs):
	task = s._task_queue.popleft()
	cancelled = getattr(task, "cancelled", None)
	if not cancelled:
	s.running_tasks.add(task)
	task.addExitListener(s._task_exit)
	task.start()
finally:
	s._scheduling = false
}

func(s*SequentialTaskQueue) _task_exit( task) {
	s.running_tasks.remove(task)
	if s._task_queue:
	s.schedule()
}

func(s*SequentialTaskQueue) clear() {
	for task
		in
	s._task_queue:
	task.cancel()
	s._task_queue.clear()

	for task
		in
	list(s.running_tasks):
	task.cancel()
}

@coroutine
func(s*SequentialTaskQueue) wait() {
	while
s:
	task = next(iter(s.running_tasks), None)
	if task is
None:
	yield
	asyncio.sleep(0)
	else:
	yield
	task.async_wait()
}

func(s*SequentialTaskQueue) __bool__() bool {
	return bool(len(s._task_queue) != 0 || len(s.running_tasks) != 0)
}

func(s*SequentialTaskQueue) __len__() int {
	return len(s._task_queue) + len(s.running_tasks)
}

type SpawnProcess struct {
	*SubProcess
	_CGROUP_CLEANUP_RETRY_MAX int
	_spawn_kwarg_names []string

	// slot
	opt_name,
	uid, gid, groups, umask, logfile,
	path_lookup, pre_exec, close_fds, cgroup,
	unshare_ipc, unshare_mount, unshare_pid, unshare_net,
	_pipe_logger, _selinux_type string
	fd_pipes map[int]int
	args     []string
	env      map[string]string
}

func(s *SpawnProcess) _start(){
	if s.fd_pipes == nil{
		s.fd_pipes =map[int]int{}
	}else {
		s.fd_pipes = s.fd_pipes
	}
	fd_pipes := s.fd_pipes

	master_fd, slave_fd := s._pipe()

	can_log := s._can_log(slave_fd)
	log_file_path := s.logfile
	if !can_log{
		log_file_path = ""
	}

	var null_input int
	if _, ok := fd_pipes[0]; ! s.background|| ok {
		//pass
	}else{
		null_input, _ = syscall.Open("/dev/null", os.O_RDWR, 0655)
		fd_pipes[0] = null_input
	}

	if _, ok := fd_pipes[0]; !ok {
		fd_pipes[0] = int(atom.getStdin().Fd())
	}
	if _, ok := fd_pipes[1]; !ok {
		fd_pipes[1] = syscall.Stdout
	}
	if _, ok := fd_pipes[2]; !ok {
		fd_pipes[2] = syscall.Stderr
	}

	fd_pipes_orig := map[int]int{}
	for k, v := range fd_pipes{
		fd_pipes_orig[k]=v
	}

	if log_file_path != "" || s.background{
		fd_pipes[1] = slave_fd
		fd_pipes[2] = slave_fd
	}else{
		s._dummy_pipe_fd = slave_fd
		fd_pipes[slave_fd] = slave_fd
	}

	kwargs = {}
	for k in s._spawn_kwarg_names{
		versions.v = getattr(s, k)
		if v != nil{
		kwargs[k] = v
	}
	}

	kwargs["fd_pipes"] = fd_pipes
	kwargs["returnpid"] = true
	kwargs.pop("logfile", nil)

	retval := s._spawn(s.args, **kwargs)

	syscall.Close(slave_fd)
	if null_input != 0 {
		syscall.Close(null_input)
	}

	if isinstance(retval, int):
	s.returncode = retval
	s._async_wait()
	return

	s.pid = retval[0]

	stdout_fd = nil
	if can_log && ! s.background:
	stdout_fd = syscall.Dup(string(fd_pipes_orig[1]))
	if sys.hexversion < 0x3040000 && fcntl != nil:
try:
	fcntl.FD_CLOEXEC
	except AttributeError:
	pass
	else:
	fcntl.fcntl(stdout_fd, fcntl.F_SETFD,
		fcntl.fcntl(stdout_fd,
			fcntl.F_GETFD) | fcntl.FD_CLOEXEC)

	s._pipe_logger = PipeLogger(background=s.background,
		scheduler=s.scheduler, input_fd=master_fd,
		log_file_path=log_file_path,
		stdout_fd=stdout_fd)
	s._pipe_logger.addExitListener(s._pipe_logger_exit)
	s._pipe_logger.start()
	s._registered = true
}


func(s *SpawnProcess) _can_log( slave_fd int)bool{
	return true
}

func(s *SpawnProcess) _pipe()(int, int){
	r :=make([]int, 2)
	syscall.Pipe(r)
	return r[0],r[1]
}

func(s *SpawnProcess) _spawn(args []string, **kwargs) {
	spawn_func := process.spawn

	if s._selinux_type != nil {
		spawn_func = portage.selinux.spawn_wrapper(spawn_func,
			s._selinux_type)
		if args[0] != _const.BashBinary {
			args = append([]string{_const.BashBinary, "-c", "exec \"$@\"", args[0]}, args...)
		}
	}

	return spawn_func(args, **kwargs)
}

// ignored
func(s *SpawnProcess) _pipe_logger_exit(){
	s._pipe_logger = nil
	s._async_waitpid()
}

func(s *SpawnProcess) _unregister(){
	s.SubProcess._unregister()
	if s.cgroup != nil {
		s._cgroup_cleanup()
		s.cgroup = nil
	}
	if s._pipe_logger != nil {
		s._pipe_logger.cancel()
		s._pipe_logger = nil
	}
}

func(s *SpawnProcess) _cancel(){
	s.SubProcess._cancel()
	s._cgroup_cleanup()
}

func(s *SpawnProcess) _cgroup_cleanup() {
	if s.cgroup != nil {
		get_pids := func(cgroup string) []int {
			f, err := os.Open(filepath.Join(cgroup, "cgroup.procs"))
			var b []byte
			if err == nil {
				b, err = ioutil.ReadAll(f)
			}
			if err != nil {
				return []int{}
			}
			ps := []int{}
			for _, p := range strings.Fields(string(b)) {
				pi, _ := strconv.Atoi(p)
				ps = append(ps, pi)
			}
			return ps
		}
		kill_all := func(pids []int, sig syscall.Signal) {
			for _, p := range pids {
				err := syscall.Kill(p, sig)
				if err != nil {
					//except OSError as e:
					if err == syscall.EPERM {
						msg.WriteMsgLevel(fmt.Sprintf("!!! kill: (%i) - Operation not permitted\n", p), 40, -1)
					} else if err != syscall.ESRCH {
						//raise
					}
				}
			}
		}
		remaining := s._CGROUP_CLEANUP_RETRY_MAX
		var pids []int
		for remaining > 0 {
			remaining -= 1
			pids = get_pids(s.cgroup)
			if len(pids) != 0 {
				kill_all(pids, syscall.SIGKILL)
			} else {
				break
			}
		}

		if len(pids) > 0 {
			msg := []string{}
			pidss := []string{}
			for _, p := range pids {
				pidss = append(pidss, fmt.Sprint(p))
			}
			msg = append(msg,
				fmt.Sprintf("Failed to kill pid(s) in '%(cgroup)s': %(pids)s",
					filepath.Join(s.cgroup, "cgroup.procs", strings.Join(pidss, " "))))

			s._elog("eerror", msg)
		}

		err := os.RemoveAll(s.cgroup.Name())
		if err != nil {
			//except OSError:
			//pass
		}
	}
}

func(s *SpawnProcess) _elog(elog_funcname string, lines []string){
	var elog_func func(string)
	switch elog_funcname {
	case "eerror":
		elog_func = output.NewEOutput(false).eerror
	}
	for _, line := range lines{
		elog_func(line)
	}
}

func NewSpawnProcess(args []string, background bool, env map[string]string, fd_pipes map[int]int, scheduler *SchedulerInterface, logfile string) *SpawnProcess {
	s := &SpawnProcess{}

	s._spawn_kwarg_names = []string{"env", "opt_name", "fd_pipes",
		"uid", "gid", "groups", "umask", "logfile",
		"path_lookup", "pre_exec", "close_fds", "cgroup",
		"unshare_ipc", "unshare_mount", "unshare_pid", "unshare_net"}
	s.args =args
	s.background = background
	s.env = env
	s.scheduler = scheduler
	s.logfile = logfile
	s.fd_pipes = fd_pipes
	s._CGROUP_CLEANUP_RETRY_MAX = 8
	s.SubProcess = NewSubProcess()
	return s
}


type SubProcess struct {
	*AbstractPollTask
	pid, _waitpid_id int
	_dummy_pipe_fd int
	_files []*os.File
	_cancel_timeout int
}

func (s *SubProcess) _poll() *int{
	return s.returncode
}

func (s *SubProcess) _cancel() {
	if s.isAlive() && s.pid != 0 {
		err := syscall.Kill(s.pid, syscall.SIGTERM)
		if err != nil {
			//except OSError as e:
			if err == syscall.EPERM {
				msg.WriteMsgLevel(fmt.Sprintf("!!! kill: (%i) - Operation not permitted\n", s.pid), 40, -1)
			} else if err != syscall.ESRCH {
				//raise
			}
		}
	}
}

func (s *SubProcess) _async_wait() {
	if s.returncode == nil {
		//raise asyncio.InvalidStateError('Result is not ready for %s' % (s,))
	} else {
		s.AbstractPollTask._async_wait()
	}
}

func (s *SubProcess) _async_waitpid() {
	if s.returncode != nil {
		s._async_wait()
	} else if s._waitpid_id == 0 {
		s._waitpid_id = s.pid
		s.scheduler._asyncio_child_watcher.add_child_handler(s.pid, s._async_waitpid_cb)

	}
}

func (s *SubProcess) _async_waitpid_cb( pid, returncode int) {
	if pid != s.pid {
		//raise AssertionError("expected pid %s, got %s" % (s.pid, pid))
	}
	s.returncode = &returncode
	s._async_wait()
}

func (s *SubProcess) _orphan_process_warn(){
}

func (s *SubProcess) _unregister() {
	s._registered = false
	if s._waitpid_id != 0 {
		s.scheduler._asyncio_child_watcher.remove_child_handler(s._waitpid_id)
		s._waitpid_id = 0
	}

	if s._files != nil {
		for _, f := range s._files {
			f.Close()
		}
		s._files = nil
	}
}

func NewSubProcess() *SubProcess {
	s := &SubProcess{}
	s._cancel_timeout = 1
	s.AbstractPollTask = NewAbstractPollTask()
	return s
}

type TaskSequence struct{
	*CompositeTask
	_task_queue [] *MiscFunctionsProcess
}

// nil
func NewTaskSequence(scheduler *SchedulerInterface) *TaskSequence {
	t := &TaskSequence{}

	t.AsynchronousTask = NewAsynchronousTask(scheduler)
	t._task_queue = []*MiscFunctionsProcess{}
	return t
}

func (t *TaskSequence) add(task *MiscFunctionsProcess) {
	t._task_queue = append(t._task_queue, task)
}

func (t *TaskSequence) _start() {
	t._start_next_task()
}

func (t *TaskSequence) _cancel() {
	t._task_queue = []*MiscFunctionsProcess{}
	t.CompositeTask._cancel()
}

func (t *TaskSequence) _start_next_task() {
	if len(t._task_queue) == 0 {
		t._current_task = nil
		i := 0
		t.returncode = &i
		t.wait()
		return
	}
	task := t._task_queue[0]
	t._task_queue = t._task_queue[1:]

	t._start_task(task, t._task_exit_handler)
}

func (t *TaskSequence) _task_exit_handler( task) {
	if t._default_exit(task) != 0 {
		t.wait()
	}else if len(t._task_queue) > 0 {
		t._start_next_task()
	}else {
		t._final_exit(task)
		t.wait()
	}
}

func (t *TaskSequence) __bool__() bool {
	return len(t._task_queue) > 0
}

func (t *TaskSequence) __len__() int {
	return len(t._task_queue)
}


type UninstallFailure struct{
	*exception.PortageException
	status int
}

func NewUninstallFailure (*pargs) *UninstallFailure {
	u := &UninstallFailure{}
	u.PortageException = exception.PortageException(pargs)
	u.status = 1
	if len(pargs) > 0 {
		u.status = pargs[0]
	}
	return u
}

type UnmergeDepPriority struct{
	*AbstractDepPriority
	MAX , SOFT, MIN int
	// slots
	optional bool
	ignored, satisfied
}

func NewUnmergeDepPriority(**kwargs)*UnmergeDepPriority {
	u := &UnmergeDepPriority{}

	u.AbstractDepPriority = NewAbstractDepPriority(**kwargs)
	u.MAX    =  0
	u.SOFT   = -3
	u.MIN    = -3

	if u.buildtime {
		u.optional = true
	}
	return u
}

func(u*UnmergeDepPriority) __int__() int {
	if u.runtime_slot_op {
		return 0
	}
	if u.runtime {
		return -1
	}
	if u.runtime_post {
		return -2
	}
	if u.buildtime {
		return -3
	}
	return -3
}

func(u*UnmergeDepPriority) __str__() string {
	if u.ignored {
		return "ignored"
	}
	if u.runtime_slot_op {
		return "hard slot op"
	}
	myvalue := u.__int__()
	if myvalue > u.SOFT {
		return "hard"
	}
	return "soft"
}

type ForkProcess struct {
	*SpawnProcess
}

// nil
func(f *ForkProcess) _spawn(args, fd_pipes=nil, **kwargs){
	parent_pid := os.Getpid()
	pid = nil
try:
	pid = os.fork()

	if pid != 0:
	if not isinstance(pid, int):
	raise AssertionError(
		"fork returned non-integer: %s" % (repr(pid),))
	return [pid]

	rval = 1
try:

	signal.signal(signal.SIGINT, signal.SIG_DFL)
	signal.signal(signal.SIGTERM, signal.SIG_DFL)

	signal.signal(signal.SIGCHLD, signal.SIG_DFL)
try:
	wakeup_fd = signal.set_wakeup_fd(-1)
	if wakeup_fd > 0:
	syscall.Close(wakeup_fd)
	except (ValueError, OSError):
	pass

	_close_fds()
	_setup_pipes(fd_pipes, false)

	rval := f._run()
	except SystemExit:
	raise
except:
	traceback.print_exc()
	sys.stderr.flush()
finally:
	os._exit(rval)

finally:
	if pid == 0 || (pid == nil && syscall.Getpid() != parent_pid):
	os._exit(1)
}

func(f *ForkProcess) _run(){
	panic("not implemented")
	//raise NotImplementedError(f)
}

func NewForkProcess() *ForkProcess {
	f := &ForkProcess{}
	f.SpawnProcess= NewSpawnProcess()

	return f
}

type MergeProcess struct {
	*ForkProcess
	settings *config.Config
	mydbapi *dbapi.vardbapi
	vartree *dbapi.varTree
	mycat, mypkg,  treetype, blockers, pkgloc, infloc, myebuild,
	  prev_mtimes, unmerge, _buf   string
	_elog_reader_fd int
	_elog_keys map[string]bool
	postinst_failure, _locked_vdb bool
}

func(m *MergeProcess)  _start() {
	cpv := fmt.Sprintf("%s/%s", m.mycat, m.mypkg)
	settings := m.settings
	if _, ok := settings.configDict["pkg"]["EAPI"]; cpv != settings.mycpv.string || !ok {
		settings.reload()
		settings.reset(0)
		settings.SetCpv(versions.NewPkgStr(cpv, nil, nil, "", "", "", 0, 0, "", 0, nil), m.mydbapi)
	}

	if _, ok := settings.Features.Features["merge-sync"]; runtime.GOOS == "Linux" && ok {
		//find_library("c")
	}

	if m.fd_pipes == nil {
		m.fd_pipes = map[int]int{}
	} else {
		m.fd_pipes = m.fd_pipes
	}
	if _, ok := m.fd_pipes[0]; !ok {
		m.fd_pipes[0] = int(atom.getStdin().Fd())
	}

	m.ForkProcess._start()
}

func(m *MergeProcess) _lock_vdb(){

	if  _, ok :=  m.settings.Features.Features["parallel-install"]; !ok {
		m.vartree.dbapi.lock()
		m._locked_vdb = true
	}
}

func(m *MergeProcess) _unlock_vdb(){
	if m._locked_vdb{
		m.vartree.dbapi.unlock()
		m._locked_vdb = false
	}
}

// true means none
func(m *MergeProcess) _elog_output_handler() bool {
	output := m._read_buf(m._elog_reader_fd)
	if len(output) > 0 {
		lines := strings.Split(string(output), "\n")
		if len(lines) == 1 {
			m._buf += lines[0]
		} else {
			lines[0] = m._buf + lines[0]
			m._buf = lines[len(lines)-1]
			lines = lines[:len(lines)-1]
			out := &bytes.Buffer{}
			for _, line := range lines {
				s4 := strings.SplitN(line, " ", 4)
				funcname, phase, key, msg := s4[0], s4[1], s4[2], s4[3]
				m._elog_keys[key] = true
				var reporter func(msg string, phase string, key string, out io.Writer)
				switch funcname {
				case "eerror":
					reporter = elog.eerror
				case "eqawarn":
					reporter = elog.eqawarn
				case "einfo":
					reporter = elog.einfo
				case "ewarn":
					reporter = elog.ewarn
				case "elog":
					reporter = elog.elog
				}
				reporter(msg, phase, key, out)
			}
		}
	} else if output != nil {
		m.scheduler.remove_reader(m._elog_reader_fd)
		syscall.Close(m._elog_reader_fd)
		m._elog_reader_fd = 0
		return false
	}
	return true
}

func(m *MergeProcess) _spawn( args, fd_pipes map[int]int, **kwargs) {
	r := make([]int, 2)
	syscall.Pipe(r)
	elog_reader_fd, elog_writer_fd := r[0], r[1]

	fcntl.fcntl(elog_reader_fd, fcntl.F_SETFL,
		fcntl.fcntl(elog_reader_fd, fcntl.F_GETFL)|syscall.O_NONBLOCK)

	var blockers = nil
	if m.blockers != nil {
		blockers = m.blockers()
	}
	mylink := dbapi.NewDblink(m.mycat, m.mypkg, "", m.settings,
		m.treetype, m.vartree,
		blockers, nil, elog_writer_fd)
	fd_pipes[elog_writer_fd] = elog_writer_fd
	m.scheduler.add_reader(elog_reader_fd, m._elog_output_handler)

	m._lock_vdb()
	counter := 0
	if !m.unmerge {
		counter = m.vartree.dbapi.counter_tick()
	}

	parent_pid := syscall.Getpid()
	pid := 0
try:
	pid = syscall.fork()

	if pid != 0 {
		if not isinstance(pid, int):
		raise
		AssertionError(
			"fork returned non-integer: %s" % (repr(pid), ))

		syscall.Close(elog_writer_fd)
		m._elog_reader_fd = elog_reader_fd
		m._buf = ""
		m._elog_keys = map[string]bool{}
		elog.collect_messages(mylink.mycpv.string, nil)

		if m.vartree.dbapi._categories != nil {
			m.vartree.dbapi._categories = nil
		}
		m.vartree.dbapi._pkgs_changed = true
		m.vartree.dbapi._clear_pkg_cache(mylink)

		return []int{pid}
	}

	syscall.Close(elog_reader_fd)

	signal.signal(signal.SIGINT, signal.SIG_DFL)
	signal.signal(signal.SIGTERM, signal.SIG_DFL)

	signal.signal(signal.SIGCHLD, signal.SIG_DFL)
try:
	wakeup_fd := signal.set_wakeup_fd(-1)
	if wakeup_fd > 0 {
		syscall.Close(wakeup_fd)
	}
	except(ValueError, OSError):
	pass

	locks._close_fds()
	process._setup_pipes(fd_pipes, false)

	output.HaveColor = m.settings.ValueDict["NOCOLOR"] == "yes" || m.settings.ValueDict["NOCOLOR"] == "true"

	m.vartree.dbapi._flush_cache_enabled = false

	if !m.unmerge {
		if m.settings.ValueDict["PORTAGE_BACKGROUND"] == "1" {
			m.settings.ValueDict["PORTAGE_BACKGROUND_UNMERGE"] = "1"
		} else {
			m.settings.ValueDict["PORTAGE_BACKGROUND_UNMERGE"] = "0"
		}
		m.settings.BackupChanges("PORTAGE_BACKGROUND_UNMERGE")
	}
	m.settings.ValueDict["PORTAGE_BACKGROUND"] = "subprocess"
	m.settings.BackupChanges("PORTAGE_BACKGROUND")

	rval := 1
try:
	if m.unmerge {
		if !mylink.exists() {
			rval = 0
		} else if mylink.unmerge(nil, true, m.prev_mtimes, nil, "", nil) == 0{
			mylink.lockdb()
			//try:
			mylink.delete()
			//finally:
			mylink.unlockdb()
			rval = 0
		}
	} else {
		rval = mylink.merge(m.pkgloc, m.infloc,
			m.myebuild, false, m.mydbapi,
			m.prev_mtimes, counter)
	}
	except
SystemExit:
	raise
except:
	traceback.print_exc()
	sys.stderr.flush()
finally:
	syscall.Exit(rval)

finally:
	if pid == 0 || (pid == 0 && syscall.Getpid() != parent_pid) {
		os.Exit(1)
	}
}


func(m *MergeProcess) _async_waitpid_cb( *args, **kwargs){
	m.ForkProcess._async_waitpid_cb( *args, **kwargs)
	if *m.returncode == _const.ReturncodePostinstFailure {
		m.postinst_failure = true
		*m.returncode = syscall.F_OK
	}
}

func(m *MergeProcess) _unregister() {
	if !m.unmerge {
		//try:
		m.vartree.dbapi.aux_get(m.settings.mycpv.string, map[string]bool{"EAPI": true}, "")
		//except KeyError:
		//pass
	}

	m._unlock_vdb()
	if m._elog_reader_fd != nil {
		m.scheduler.remove_reader(m._elog_reader_fd)
		syscall.Close(m._elog_reader_fd)
		m._elog_reader_fd = nil
	}
	if m._elog_keys != nil {
		for key := range m._elog_keys {
			elog.elog_process(key, m.settings, []string{"prerm", "postrm"})
		}
		m._elog_keys = nil
	}
	m.ForkProcess._unregister()
}

func NewMergeProcess(mycat, mypkg string, settings *config.Config,treetype string,
	vartree *dbapi.varTree, scheduler *SchedulerInterface, background bool, blockers interface{},
pkgloc, infloc, myebuild string,mydbapi dbapi.IDbApi,prev_mtimes interface{},
logfile string, fd_pipes map[int]int) *MergeProcess {
	m := &MergeProcess{}
	m.ForkProcess = NewForkProcess()
	m.mycat = mycat
	m.mypkg = mypkg
	m.settings = settings
	m.treetype = treetype
	m.vartree = vartree
	m.scheduler = scheduler
	m.background = background
	m.blockers = blockers
	m.mydbapi = mydbapi
	m.prev_mtimes = prev_mtimes
	m.logfile = logfile
	m.fd_pipes = fd_pipes

	return m
}

type  SchedulerInterface struct {
	// slot
	add_reader         func(int, func() bool)
	add_writer         func()
	remove_reader      func(int)
	call_soon          func(func())
	create_future      func() interfaces.IFuture
	run_until_complete func(interfaces.IFuture)
	_is_background     func() bool
	is_running         func() bool
	call_at,
	call_exception_handler,
	call_later,
	call_soon_threadsafe,
	close,
	default_exception_handler,
	get_debug,
	is_closed,
	remove_writer,
	run_in_executor
	set_debug,
	time,
	_asyncio_child_watcher,
	_asyncio_wrapper
	_event_loop string
}

var _event_loop_attrs = []string{
	"add_reader",
	"add_writer",
	"call_at",
	"call_exception_handler",
	"call_later",
	"call_soon",
	"call_soon_threadsafe",
	"close",
	"create_future",
	"default_exception_handler",
	"get_debug",
	"is_closed",
	"is_running",
	"remove_reader",
	"remove_writer",
	"run_in_executor",
	"run_until_complete",
	"set_debug",
	"time",

	"_asyncio_child_watcher",
	"_asyncio_wrapper",
}

// nil
func NewSchedulerInterface(event_loop, is_background func()bool, **kwargs)*SchedulerInterface {
	s := &SchedulerInterface{}
	SlotObject.__init__(s, **kwargs)
	s._event_loop = event_loop
	if is_background == nil {
		is_background = s._return_false
	}
	s._is_background = is_background
	for kfilter_loglevels
	in
	s._event_loop_attrs {
		setattr(s, k, getattr(event_loop, k))
	}
	return s
}

func (s *SchedulerInterface) _return_false() bool{
	return false
}

// "", false, 0, -1
func (s *SchedulerInterface) output( msg , log_path string, background bool, level, noiselevel int) {

	global_background := s._is_background()
	if !background || global_background {
		background = global_background
	}

	msg_shown := false
	if !background {
		msg.WriteMsgLevel(msg, level, noiselevel)
		msg_shown = true
	}

	if log_path != "" {
		f, err := os.OpenFile(log_path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
		if err != nil {
			//except IOError as e:
			if err != syscall.ENOENT && err != syscall.ESTALE {
				//raise
			}
			if !msg_shown {
				msg.WriteMsgLevel(msg, level, noiselevel)
			}
		} else {
			if strings.HasSuffix(log_path, ".gz") {
				g := gzip.NewWriter(f)
				g.Write([]byte(msg))
			} else {
				f.Write([]byte(msg))
			}
			f.Close()
		}
	}
}

type AsyncTaskFuture struct {
	*AsynchronousTask
	// slot
	future interfaces.IFuture
}

func (a*AsyncTaskFuture) _start() {
	a.future.add_done_callback(a._done_callback)
}

func (a*AsyncTaskFuture) _cancel() {
	if ! a.future.done() {
		a.future.cancel()
	}
}

func (a*AsyncTaskFuture) _done_callback(future interfaces.IFuture, err error) {
	if future.cancelled() {
		a.cancelled = true
		i := -int(unix.SIGINT)
		a.returncode = &i
	} else if future.exception() == nil {
		i := 0
		a.returncode = &i
	} else {
		i := 1
		a.returncode = &i
	}
	a._async_wait()
}

func NewAsyncTaskFuture(future interfaces.IFuture)*AsyncTaskFuture {
	a := &AsyncTaskFuture{}
	a.AsynchronousTask = NewAsynchronousTask()
	a.future = future
	return a
}

type AsyncFunction struct{
	*ForkProcess

	// slot
	_async_func_reader *PipeReader
	_async_func_reader_pw int
	fun func() interface{}
	result interface{}
}

func (a*AsyncFunction) _start() {
	p2 := make([]int, 2)
	syscall.Pipe(p2)
	pr, pw := p2[0], p2[1]
	if a.fd_pipes ==nil{
		a.fd_pipes =map[int]int{}
	}
	a.fd_pipes[pw] = pw
	a._async_func_reader_pw = pw
	a._async_func_reader = NewPipeReader(map[string] int{"input": pr},  a.scheduler)
	a._async_func_reader.addExitListener(a._async_func_reader_exit)
	a._async_func_reader.start()
	a.ForkProcess._start()
	syscall.Close(pw)
}

func (a*AsyncFunction) _run() int {
//try:
	result := a.fun()
	ogórek.NewEncoder(os.NewFile(uintptr(a._async_func_reader_pw), "")).Encode(result)
	//except Exception:
	//traceback.print_exc()
	//return 1

	return 0
}

func (a*AsyncFunction) _async_waitpid() {
	if a._async_func_reader ==nil {
		a.ForkProcess._async_waitpid()
	}
}

func (a*AsyncFunction)_async_func_reader_exit( pipe_reader io.Reader){
//try:
	a.result, _ = ogórek.NewDecoder(pipe_reader).Decode()
	//except Exception:
	//pass
	a._async_func_reader = nil
	if a.returncode ==nil {
		a._async_waitpid()
	}else {
		a._unregister()
		a._async_wait()
	}
}

func (a*AsyncFunction) _unregister() {
	a.ForkProcess._unregister()

	pipe_reader := a._async_func_reader
	if pipe_reader != nil {
		a._async_func_reader = nil
		pipe_reader.removeExitListener(a._async_func_reader_exit)
		pipe_reader.cancel()
	}
}

func NewAsyncFunction(fun func() interface{})*AsyncFunction {
	a:=&AsyncFunction{}
	a.fun = fun
	return a
}
