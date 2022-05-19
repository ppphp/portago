package permissions

import (
	"github.com/ppphp/portago/pkg/data"
	"os"
	"syscall"
)

func doStat(fname string, followLinks bool) (os.FileInfo, error) {
	if followLinks {
		return os.Stat(fname)
	} else {
		return os.Lstat(fname)
	}
}

// -1,-1,-1,-1,nil,true
func applyPermissions(filename string, uid, gid uint32, mode, mask os.FileMode, statCached os.FileInfo, followLinks bool) bool {
	modified := false
	if statCached == nil {
		statCached, _ = doStat(filename, followLinks)
	}
	if (int(uid) != -1 && uid != statCached.Sys().(*syscall.Stat_t).Uid) || (int(gid) != -1 && gid != statCached.Sys().(*syscall.Stat_t).Gid) {
		if followLinks {
			os.Chown(filename, int(uid), int(gid))
		} else {
			os.Lchown(filename, int(uid), int(gid))
		}
		modified = true
	} // TODO check errno
	newMode := os.FileMode(0) // uint32(-1)
	stMode := statCached.Mode() & 07777
	if mask >= 0 {
		if int(mode) == -1 {
			mode = 0
		} else {
			mode = mode & 07777
		}
		if (stMode&mask != mode) || ((mask^stMode)&stMode != stMode) {
			newMode = mode | stMode
			newMode = (mask ^ newMode) & newMode
		}
	} else if int(mode) != -1 {
		mode = mode & 07777
		if mode != stMode {
			newMode = mode
		}
	}
	if modified && int(stMode) == -1 && (int(stMode)&syscall.S_ISUID != 0 || int(stMode)&syscall.S_ISGID != 0) {
		if int(mode) == -1 {
			newMode = stMode
		} else {
			mode = mode & 0777
			if mask >= 0 {
				newMode = mode | stMode
				newMode = (mask ^ newMode) & newMode
			} else {
				newMode = mode
			}
		}
	}
	if !followLinks && statCached.Mode()&os.ModeSymlink != 0 {
		newMode = 0
		newMode--
	}
	if int(newMode) != -1 {
		os.Chmod(filename, os.FileMode(newMode))
	}
	return modified
}

// -1, nil, true
func Apply_stat_permissions(filename string, newStat os.FileInfo, mask os.FileMode, statCached os.FileInfo, followLinks bool) bool {
	st := newStat.Sys().(*syscall.Stat_t)
	return apply_secpass_permissions(filename, st.Uid, st.Gid, newStat.Mode(), mask, statCached, followLinks)
}

// -1, -1, -1, -1, nil, true
func apply_secpass_permissions(filename string, uid, gid uint32, mode, mask os.FileMode, statCached os.FileInfo, followLinks bool) bool {

	if statCached == nil {
		statCached, _ = doStat(filename, followLinks)
	}

	allApplied := true

	if (int(uid) != -1 || int(gid) != -1) && data.Secpass != nil && *data.Secpass < 2 {
		if int(uid) != -1 && uid != statCached.Sys().(*syscall.Stat_t).Uid {
			allApplied = false
			uid = 0
			uid--
		}
		gs, _ := os.Getgroups()
		in := false
		for _, g := range gs {
			if g == int(gid) {
				in = true
				break
			}
		}
		if int(uid) != -1 && gid != statCached.Sys().(*syscall.Stat_t).Gid && !in {
			allApplied = false
			gid = 0
			gid--
		}
	}

	applyPermissions(filename, uid, gid, mode, mask,
		statCached, followLinks)
	return allApplied
}
