# Restarted

Since go1.18 brings the type parameter, I continue.

# portago

This is a package management tool written in go and copied from portage shamelessly.

Package Management by go can remove annoying python dependency, though it is meaningless in gentoo with additional stupid go dependency.

Honestly, the main problem is give the package manager a static type.

now based on portage master, Feb 21, 2022

14d9c755f7534e23f10719d0fe6c04b18534e854

# Roadmap

- package dependency and file split
  - good
    - const
    - eapi
    - process
    - checksum
    - output
    - data
    - progress
    - xpak
    - src
    - versions
    - getbinpkg
    - binrepo
    - env
  - bad
    - cache
    - dbapi
    - dep
    - ebuild
    - elog
    - emaint
    - emerge
    - locks
    - manifest
    - metadata
    - portage
    - repository
    - sets
    - sync
    - util
- ebuild sync runnable
  - [ ] can build binary (used to)
  - [ ] can synchronize repo
  - [ ] can test functions
  - [ ] can configure
- python files rewrite
- shell files rewrite

TODO:
- gemato
- bsd_chflags
- shlex test
- configparser test
- selinux


