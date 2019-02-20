package atom

// https://devmanual.gentoo.org/ebuild-writing/functions/index.html

func pkgPretend() {

}

func pkgNoFetch() {

}

func clean() string {
	return `
PVR=2.10
POSTGRES_TARGETS=
OFED_DRIVERS=
NETBEANS_MODULES=
PORTAGE_BUILDDIR=/var/tmp/portage/app-misc/hello-2.10
ENLIGHTENMENT_MODULES=
PORTAGE_INST_UID=0
LIRC_DEVICES=
ARCH=amd64
LCD_DEVICES=
DISTDIR=/var/tmp/portage/app-misc/hello-2.10/distdir
CBUILD=x86_64-pc-linux-gnu
USE_EXPAND_VALUES_KERNEL=AIX Darwin FreeBSD freemint HPUX linux NetBSD OpenBSD SunOS Winnt
A=hello-2.10.tar.gz
ALSA_CARDS=
D=/var/tmp/portage/app-misc/hello-2.10/image/
VOICEMAIL_STORAGE=
P=hello-2.10
T=/var/tmp/portage/app-misc/hello-2.10/temp
GRUB_PLATFORMS=
ENV_UNSET=DBUS_SESSION_BUS_ADDRESS DISPLAY GOBIN PERL5LIB PERL5OPT PERLPREFIX PERL_CORE PERL_MB_OPT PERL_MM_OPT XAUTHORITY XDG_CACHE_HOME XDG_CONFIG_HOME XDG_DATA_HOME XDG_RUNTIME_DIR
PORTAGE_INST_GID=0
ABI_PPC=
LESS=-R -M --shift 5
OFFICE_IMPLEMENTATION=
OPENGL_PROFILE=xorg-x11
IUSE_IMPLICIT=abi_x86_64 prefix prefix-chain prefix-guest
CATEGORY=app-misc
CPU_FLAGS_ARM=
ABI=amd64
USE_EXPAND_VALUES_ARCH=alpha amd64 amd64-fbsd amd64-linux arm arm64 hppa ia64 m68k m68k-mint mips ppc ppc64 ppc64-linux ppc-aix ppc-macos s390 sh sparc sparc64-solaris sparc-solaris x64-cygwin x64-macos x64-solaris x86 x86-cygwin x86-fbsd x86-linux x86-macos x86-solaris x86-winnt
PORTAGE_BASHRC=/etc/portage/bashrc
PORTAGE_COLORMAP=GOOD=$'[32;01m'
WARN=$'[33;01m'
BAD=$'[31;01m'
HILITE=$'[36m'
BRACKET=$'[34;01m'
NORMAL=$'[0m'
USE_EXPAND_UNPREFIXED=ARCH
BUILD_PREFIX=/var/tmp/portage
INHERITED=
APACHE2_MODULES=
LIBREOFFICE_EXTENSIONS=
REQUIRED_USE=
COLORTERM=truecolor
OPENMPI_FABRICS=
USE=abi_x86_64 amd64 elibc_glibc kernel_linux nls userland_GNU
ROS_MESSAGES=
PORTAGE_REPO_NAME=gentoo
ED=/var/tmp/portage/app-misc/hello-2.10/image/
SANDBOX_LOG=app-misc_-_hello-2.10
MULTILIB_ABIS=amd64 x86
MULTILIB_STRICT_DIRS=/lib32 /lib /usr/lib32 /usr/lib /usr/kde/*/lib32 /usr/kde/*/lib /usr/qt/*/lib32 /usr/qt/*/lib /usr/X11R6/lib32 /usr/X11R6/lib
CURL_SSL=
SUDO_COMMAND=/usr/bin/emerge hello
CFLAGS=-march=native -Ofast -pipe
GCC_SPECS=
PORTAGE_DEPCACHEDIR=/var/cache/edb/dep
BDEPEND=
DEFINED_PHASES=configure
PORTAGE_BZIP2_COMMAND=bzip2
PORTAGE_PYTHON=/usr/bin/python3.5m
MERGE_TYPE=source
PHP_TARGETS=
EROOT=/
CALLIGRA_FEATURES=
USE_EXPAND=ABI_MIPS ABI_PPC ABI_S390 ABI_X86 ALSA_CARDS APACHE2_MODULES APACHE2_MPMS CALLIGRA_FEATURES CAMERAS COLLECTD_PLUGINS CPU_FLAGS_ARM CPU_FLAGS_X86 CURL_SSL ELIBC ENLIGHTENMENT_MODULES FFTOOLS GPSD_PROTOCOLS GRUB_PLATFORMS INPUT_DEVICES KERNEL L10N LCD_DEVICES LIBREOFFICE_EXTENSIONS LIRC_DEVICES LLVM_TARGETS MONKEYD_PLUGINS NETBEANS_MODULES NGINX_MODULES_HTTP NGINX_MODULES_MAIL NGINX_MODULES_STREAM OFED_DRIVERS OFFICE_IMPLEMENTATION OPENMPI_FABRICS OPENMPI_OFED_FEATURES OPENMPI_RM PHP_TARGETS POSTGRES_TARGETS PYTHON_SINGLE_TARGET PYTHON_TARGETS QEMU_SOFTMMU_TARGETS QEMU_USER_TARGETS ROS_MESSAGES RUBY_TARGETS SANE_BACKENDS USERLAND UWSGI_PLUGINS VIDEO_CARDS VOICEMAIL_STORAGE XFCE_PLUGINS XTABLES_ADDONS
USE_EXPAND_IMPLICIT=ARCH ELIBC KERNEL USERLAND
EAPI=6
CXXFLAGS=-march=native -Ofast -pipe
LC_COLLATE=C
PORTAGE_OVERRIDE_EPREFIX=
EBUILD_PHASE=clean
ROOT=/
PORTAGE_XATTR_EXCLUDE=btrfs.* security.evm security.ima 	security.selinux system.nfs4_acl user.apache_handler 	user.Beagle.* user.dublincore.* user.mime_encoding user.xdg.*
USERLAND=GNU
PORTAGE_COMPRESS_EXCLUDE_SUFFIXES=css gif htm[l]? jp[e]?g js pdf png
PORTAGE_BUILD_GROUP=portage
NGINX_MODULES_MAIL=
GPSD_PROTOCOLS=
SANE_BACKENDS=
PORTAGE_CONFIGROOT=/
PWD=/home/ppphp
PR=r0
PORTAGE_ACTUAL_DISTDIR=/usr/portage/distfiles
PV=2.10
HOME=/var/tmp/portage/app-misc/hello-2.10/homedir
MANPAGER=manpager
IUSE=nls
PF=hello-2.10
PORTAGE_SIGPIPE_STATUS=141
PN=hello
FETCHCOMMAND_SSH=bash -c "x=\${2#ssh://} ; host=\${x%%/*} ; port=\${host##*:} ; host=\${host%:*} ; [[ \${host} = \${port} ]] && port= ; exec rsync --rsh=\"ssh \${port:+-p\${port}} \${3}\" -avP \"\${host}:/\${x#*/}\" \"\$1\"" rsync "${DISTDIR}/${FILE}" "${URI}" "${PORTAGE_SSH_OPTS}"
SLOT=0
LIBDIR_x86=lib32
L10N=
GSETTINGS_BACKEND=dconf
XFCE_PLUGINS=
PORTAGE_GID=250
OPENMPI_OFED_FEATURES=
BASH_ENV=/etc/spork/is/not/valid/profile.env
CPU_FLAGS_X86=
XDG_DATA_DIRS=/usr/local/share:/usr/share
PORTAGE_ECLASS_LOCATIONS=/usr/portage
PORTAGE_WORKDIR_MODE=0700
PORTAGE_FEATURES=assume-digests binpkg-logs config-protect-if-modified distlocks ebuild-locks fixlafiles merge-sync multilib-strict news parallel-fetch preserve-libs protect-owned sandbox sfperms strict unknown-features-warn unmerge-logs unmerge-orphans userfetch userpriv usersandbox usersync xattr
ECLASSDIR=/usr/portage/eclass
PORTAGE_ARCHLIST=alpha amd64 amd64-fbsd amd64-linux arm arm-linux arm64 arm64-linux hppa ia64 m68k m68k-mint mips ppc ppc-aix ppc-macos ppc64 ppc64-linux s390 sh sparc sparc-solaris sparc64-solaris x64-cygwin x64-macos x64-solaris x86 x86-cygwin x86-fbsd x86-linux x86-macos x86-solaris x86-winnt
VIDEO_CARDS=
FLTK_DOCDIR=/usr/share/doc/fltk-1.3.3-r3/html
FCFLAGS=-O2 -pipe
PKGDIR=/usr/portage/packages
PORTAGE_PIPE_FD=11
HDEPEND=
PORTAGE_DEBUG=0
LLVM_TARGETS=
MAKEOPTS=-j8
INPUT_DEVICES=
ABI_X86=64
PORTAGE_TMPDIR=/var/tmp
USE_EXPAND_VALUES_USERLAND=BSD GNU
QEMU_USER_TARGETS=
NOCOLOR=true
LADSPA_PATH=/usr/lib64/ladspa
COLUMNS=80
PYTHON_SINGLE_TARGET=
PORTAGE_REPOSITORIES=[DEFAULT]
auto-sync = yes
main-repo = gentoo
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[chaoslab]
auto-sync = no
location = /var/lib/layman/chaoslab
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[didactic-duck]
auto-sync = no
location = /var/lib/layman/didactic-duck
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[gentoo]
auto-sync = yes
location = /usr/portage
masters = 
priority = -1000
strict-misc-digests = true
sync-allow-hardlinks = true
sync-openpgp-key-path = /var/lib/gentoo/gkeys/keyrings/gentoo/release/pubring.gpg
sync-openpgp-key-refresh-retry-count = 40
sync-openpgp-key-refresh-retry-delay-exp-base = 2
sync-openpgp-key-refresh-retry-delay-max = 60
sync-openpgp-key-refresh-retry-delay-mult = 4
sync-openpgp-key-refresh-retry-overall-timeout = 1200
sync-rcu = false
sync-type = rsync
sync-uri = rsync://rsync.gentoo.org/gentoo-portage
sync-rsync-verify-max-age = 24
sync-rsync-verify-jobs = 1
sync-rsync-extra-opts = 
sync-rsync-verify-metamanifest = no

[gentoo-zh]
auto-sync = no
location = /var/lib/layman/gentoo-zh
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[steam-overlay]
auto-sync = no
location = /var/lib/layman/steam-overlay
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

CHOST=x86_64-pc-linux-gnu
PKGUSE=
PORTAGE_IUSE=^(abi_x86_64|alpha|amd64|amd64\-fbsd|amd64\-linux|arm|arm64|elibc_AIX|elibc_Cygwin|elibc_Darwin|elibc_DragonFly|elibc_FreeBSD|elibc_HPUX|elibc_Interix|elibc_NetBSD|elibc_OpenBSD|elibc_SunOS|elibc_Winnt|elibc_bionic|elibc_glibc|elibc_mingw|elibc_mintlib|elibc_musl|elibc_uclibc|hppa|ia64|kernel_AIX|kernel_Darwin|kernel_FreeBSD|kernel_HPUX|kernel_NetBSD|kernel_OpenBSD|kernel_SunOS|kernel_Winnt|kernel_freemint|kernel_linux|m68k|m68k\-mint|mips|nls|ppc|ppc64|ppc64\-linux|ppc\-aix|ppc\-macos|prefix|prefix\-chain|prefix\-guest|s390|sh|sparc|sparc64\-solaris|sparc\-solaris|userland_BSD|userland_GNU|x64\-cygwin|x64\-macos|x64\-solaris|x86|x86\-cygwin|x86\-fbsd|x86\-linux|x86\-macos|x86\-solaris|x86\-winnt)$
QEMU_SOFTMMU_TARGETS=
ROOTPATH=/usr/x86_64-pc-linux-gnu/gcc-bin/6.4.0:/usr/lib/llvm/6/bin:/usr/lib/llvm/5/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin
PORTAGE_PYTHONPATH=/usr/lib64/python3.5/site-packages
KEYWORDS=~amd64 ~x86 ~amd64-linux ~x86-linux
LIBDIR_x32=libx32
KERNEL=linux
PORTAGE_BASHRC_FILES=
PORTAGE_BIN_PATH=/usr/lib/portage/python3.5
LC_MESSAGES=C
EPREFIX=
ABI_MIPS=
PORTAGE_COMPRESSION_COMMAND=bzip2
TWISTED_DISABLE_WRITING_OF_PLUGIN_CACHE=1
CHOST_amd64=x86_64-pc-linux-gnu
CFLAGS_amd64=-m64
PORTAGE_INTERNAL_CALLER=1
MONKEYD_PLUGINS=
OPENMPI_RM=
USE_EXPAND_VALUES_ELIBC=AIX bionic Cygwin Darwin DragonFly FreeBSD glibc HPUX Interix mingw mintlib musl NetBSD OpenBSD SunOS uclibc Winnt
PORTDIR=/usr/portage
BOOTSTRAP_USE=cxx unicode internal-glib split-usr python_targets_python3_6 python_targets_python2_7 multilib
ELIBC=glibc
LDFLAGS_amd64=-m elf_x86_64
CFLAGS_x32=-mx32
LDFLAGS_x32=-m elf32_x86_64
SYSROOT=
CAMERAS=
MULTILIB_STRICT_DENY=64-bit.*shared object
RESUMECOMMAND_SSH=bash -c "x=\${2#ssh://} ; host=\${x%%/*} ; port=\${host##*:} ; host=\${host%:*} ; [[ \${host} = \${port} ]] && port= ; exec rsync --rsh=\"ssh \${port:+-p\${port}} \${3}\" -avP \"\${host}:/\${x#*/}\" \"\$1\"" rsync "${DISTDIR}/${FILE}" "${URI}" "${PORTAGE_SSH_OPTS}"
PYTHONDONTWRITEBYTECODE=1
PORTAGE_RESTRICT=
SHLVL=2
LANGUAGE=
LIBDIR_amd64=lib64
LICENSE=FDL-1.3 GPL-3
LDFLAGS_x86=-m elf_i386
FFTOOLS=
EBUILD=/usr/portage/app-misc/hello/hello-2.10.ebuild
FEATURES=assume-digests binpkg-logs config-protect-if-modified distlocks ebuild-locks fixlafiles merge-sync multilib-strict news parallel-fetch preserve-libs protect-owned sandbox sfperms strict unknown-features-warn unmerge-logs unmerge-orphans userfetch userpriv usersandbox usersync xattr
FFLAGS=-O2 -pipe
FILESDIR=/var/tmp/portage/app-misc/hello-2.10/files
ACCEPT_LICENSE=FDL-1.3 GPL-3
WORKDIR=/var/tmp/portage/app-misc/hello-2.10/work
UWSGI_PLUGINS=
SYMLINK_LIB=yes
CFLAGS_x86=-m32
NGINX_MODULES_HTTP=
PKG_TMPDIR=/var/tmp/portage/._unmerge_
EMERGE_FROM=ebuild
LDFLAGS=-Wl,-O1 -Wl,--as-needed
XTABLES_ADDONS=
PYTHON_TARGETS=
CHOST_x86=i686-pc-linux-gnu
IUSE_EFFECTIVE=abi_x86_64 alpha amd64 amd64-fbsd amd64-linux arm arm64 elibc_AIX elibc_Cygwin elibc_Darwin elibc_DragonFly elibc_FreeBSD elibc_HPUX elibc_Interix elibc_NetBSD elibc_OpenBSD elibc_SunOS elibc_Winnt elibc_bionic elibc_glibc elibc_mingw elibc_mintlib elibc_musl elibc_uclibc hppa ia64 kernel_AIX kernel_Darwin kernel_FreeBSD kernel_HPUX kernel_NetBSD kernel_OpenBSD kernel_SunOS kernel_Winnt kernel_freemint kernel_linux m68k m68k-mint mips nls ppc ppc-aix ppc-macos ppc64 ppc64-linux prefix prefix-chain prefix-guest s390 sh sparc sparc-solaris sparc64-solaris userland_BSD userland_GNU x64-cygwin x64-macos x64-solaris x86 x86-cygwin x86-fbsd x86-linux x86-macos x86-solaris x86-winnt
RESTRICT=
XDG_CONFIG_DIRS=/etc/xdg
PM_EBUILD_HOOK_DIR=/etc/portage/env
PROPERTIES=
DEFAULT_ABI=amd64
MULTILIB_STRICT_EXEMPT=(perl5|gcc|gcc-lib|binutils|eclipse-3|debug|portage|udev|systemd|clang|python-exec|llvm)
RPMDIR=/usr/portage/rpm
APACHE2_MPMS=
COLLECTD_PLUGINS=
ABI_S390=
NGINX_MODULES_STREAM=
PORTAGE_PYM_PATH=/usr/lib64/python3.5/site-packages
PROFILE_ONLY_VARIABLES=ARCH ELIBC IUSE_IMPLICIT KERNEL USERLAND USE_EXPAND_IMPLICIT USE_EXPAND_UNPREFIXED USE_EXPAND_VALUES_ARCH USE_EXPAND_VALUES_ELIBC USE_EXPAND_VALUES_KERNEL USE_EXPAND_VALUES_USERLAND
RUBY_TARGETS=
CVS_RSH=ssh
CHOST_x32=x86_64-pc-linux-gnux32
LESSOPEN=|lesspipe %s
PORTAGE_BUILD_USER=portage
_=/usr/bin/printenv
`
}

func pkgSetUp() string {
	return `
PVR=2.10
POSTGRES_TARGETS=
OFED_DRIVERS=
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=01;05;37;41:mi=01;05;37;41:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.cfg=00;32:*.conf=00;32:*.diff=00;32:*.doc=00;32:*.ini=00;32:*.log=00;32:*.patch=00;32:*.pdf=00;32:*.ps=00;32:*.tex=00;32:*.txt=00;32:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
NETBEANS_MODULES=
PORTAGE_BUILDDIR=/var/tmp/portage/app-misc/hello-2.10
ENLIGHTENMENT_MODULES=
PORTAGE_INST_UID=0
LIRC_DEVICES=
PKG_LOGDIR=/var/tmp/portage/app-misc/hello-2.10/temp/logging
ARCH=amd64
LCD_DEVICES=
DISTDIR=/var/tmp/portage/app-misc/hello-2.10/distdir
CBUILD=x86_64-pc-linux-gnu
USE_EXPAND_VALUES_KERNEL=AIX Darwin FreeBSD freemint HPUX linux NetBSD OpenBSD SunOS Winnt
A=hello-2.10.tar.gz
ALSA_CARDS=
D=/var/tmp/portage/app-misc/hello-2.10/image/
VOICEMAIL_STORAGE=
P=hello-2.10
T=/var/tmp/portage/app-misc/hello-2.10/temp
GRUB_PLATFORMS=
ENV_UNSET=DBUS_SESSION_BUS_ADDRESS DISPLAY GOBIN PERL5LIB PERL5OPT PERLPREFIX PERL_CORE PERL_MB_OPT PERL_MM_OPT XAUTHORITY XDG_CACHE_HOME XDG_CONFIG_HOME XDG_DATA_HOME XDG_RUNTIME_DIR
PORTAGE_INST_GID=0
ABI_PPC=
LESS=-R -M --shift 5
OFFICE_IMPLEMENTATION=
DISPLAY=:0
SUDO_GID=1000
OPENGL_PROFILE=xorg-x11
IUSE_IMPLICIT=abi_x86_64 prefix prefix-chain prefix-guest
CATEGORY=app-misc
CPU_FLAGS_ARM=
ABI=amd64
USE_EXPAND_VALUES_ARCH=alpha amd64 amd64-fbsd amd64-linux arm arm64 hppa ia64 m68k m68k-mint mips ppc ppc64 ppc64-linux ppc-aix ppc-macos s390 sh sparc sparc64-solaris sparc-solaris x64-cygwin x64-macos x64-solaris x86 x86-cygwin x86-fbsd x86-linux x86-macos x86-solaris x86-winnt
PORTAGE_BASHRC=/etc/portage/bashrc
PORTAGE_COLORMAP=GOOD=$'^[[32;01m'
WARN=$'^[[33;01m'
BAD=$'^[[31;01m'
HILITE=$'^[[36m'
BRACKET=$'^[[34;01m'
NORMAL=$'^[[0m'
USE_EXPAND_UNPREFIXED=ARCH
BUILD_PREFIX=/var/tmp/portage
APACHE2_MODULES=
INHERITED=
LIBREOFFICE_EXTENSIONS=
REQUIRED_USE=
COLORTERM=truecolor
OPENMPI_FABRICS=
USE=abi_x86_64 amd64 elibc_glibc kernel_linux nls userland_GNU
ROS_MESSAGES=
USERNAME=root
PORTAGE_REPO_NAME=gentoo
ED=/var/tmp/portage/app-misc/hello-2.10/image/
SANDBOX_LOG=app-misc_-_hello-2.10
MULTILIB_ABIS=amd64 x86
MULTILIB_STRICT_DIRS=/lib32 /lib /usr/lib32 /usr/lib /usr/kde/*/lib32 /usr/kde/*/lib /usr/qt/*/lib32 /usr/qt/*/lib /usr/X11R6/lib32 /usr/X11R6/lib
CURL_SSL=
SUDO_COMMAND=/usr/bin/emerge hello
CFLAGS=-march=native -Ofast -pipe
GCC_SPECS=
PORTAGE_DEPCACHEDIR=/var/cache/edb/dep
BDEPEND=
DEFINED_PHASES=configure
PORTAGE_BZIP2_COMMAND=bzip2
PORTAGE_PYTHON=/usr/bin/python3.5m
PHP_TARGETS=
MERGE_TYPE=source
EROOT=/
CALLIGRA_FEATURES=
USE_EXPAND=ABI_MIPS ABI_PPC ABI_S390 ABI_X86 ALSA_CARDS APACHE2_MODULES APACHE2_MPMS CALLIGRA_FEATURES CAMERAS COLLECTD_PLUGINS CPU_FLAGS_ARM CPU_FLAGS_X86 CURL_SSL ELIBC ENLIGHTENMENT_MODULES FFTOOLS GPSD_PROTOCOLS GRUB_PLATFORMS INPUT_DEVICES KERNEL L10N LCD_DEVICES LIBREOFFICE_EXTENSIONS LIRC_DEVICES LLVM_TARGETS MONKEYD_PLUGINS NETBEANS_MODULES NGINX_MODULES_HTTP NGINX_MODULES_MAIL NGINX_MODULES_STREAM OFED_DRIVERS OFFICE_IMPLEMENTATION OPENMPI_FABRICS OPENMPI_OFED_FEATURES OPENMPI_RM PHP_TARGETS POSTGRES_TARGETS PYTHON_SINGLE_TARGET PYTHON_TARGETS QEMU_SOFTMMU_TARGETS QEMU_USER_TARGETS ROS_MESSAGES RUBY_TARGETS SANE_BACKENDS USERLAND UWSGI_PLUGINS VIDEO_CARDS VOICEMAIL_STORAGE XFCE_PLUGINS XTABLES_ADDONS
USE_EXPAND_IMPLICIT=ARCH ELIBC KERNEL USERLAND
EAPI=6
CXXFLAGS=-march=native -Ofast -pipe
LC_COLLATE=C
PORTAGE_OVERRIDE_EPREFIX=
EBUILD_PHASE=setup
ROOT=/
PORTAGE_XATTR_EXCLUDE=btrfs.* security.evm security.ima         security.selinux system.nfs4_acl user.apache_handler    user.Beagle.* user.dublincore.* user.mime_encoding user.xdg.*
USERLAND=GNU
PORTAGE_COMPRESS_EXCLUDE_SUFFIXES=css gif htm[l]? jp[e]?g js pdf png
PORTAGE_BUILD_GROUP=portage
NGINX_MODULES_MAIL=
GPSD_PROTOCOLS=
SANE_BACKENDS=
PORTAGE_CONFIGROOT=/
PWD=/home/ppphp
PR=r0
PORTAGE_ACTUAL_DISTDIR=/usr/portage/distfiles
PV=2.10
HOME=/var/tmp/portage/app-misc/hello-2.10/homedir
MANPAGER=manpager
IUSE=nls
PF=hello-2.10
PORTAGE_SIGPIPE_STATUS=141
PN=hello
FETCHCOMMAND_SSH=bash -c "x=\${2#ssh://} ; host=\${x%%/*} ; port=\${host##*:} ; host=\${host%:*} ; [[ \${host} = \${port} ]] && port= ; exec rsync --rsh=\"ssh \${port:+-p\${port}} \${3}\" -avP \"\${host}:/\${x#*/}\" \"\$1\"" rsync "${DISTDIR}/${FILE}" "${URI}" "${PORTAGE_SSH_OPTS}"
SLOT=0
LIBDIR_x86=lib32
SUDO_USER=ppphp
L10N=
GSETTINGS_BACKEND=dconf
XFCE_PLUGINS=
PORTAGE_GID=250
OPENMPI_OFED_FEATURES=
BASH_ENV=/etc/spork/is/not/valid/profile.env
XDG_DATA_DIRS=/usr/local/share:/usr/share
CPU_FLAGS_X86=
PORTAGE_ECLASS_LOCATIONS=/usr/portage
PORTAGE_WORKDIR_MODE=0700
PORTAGE_FEATURES=assume-digests binpkg-logs config-protect-if-modified distlocks ebuild-locks fixlafiles merge-sync multilib-strict news parallel-fetch preserve-libs protect-owned sandbox sfperms strict unknown-features-warn unmerge-logs unmerge-orphans userfetch userpriv usersandbox usersync xattr
ECLASSDIR=/usr/portage/eclass
PORTAGE_ARCHLIST=alpha amd64 amd64-fbsd amd64-linux arm arm-linux arm64 arm64-linux hppa ia64 m68k m68k-mint mips ppc ppc-aix ppc-macos ppc64 ppc64-linux s390 sh sparc sparc-solaris sparc64-solaris x64-cygwin x64-macos x64-solaris x86 x86-cygwin x86-fbsd x86-linux x86-macos x86-solaris x86-winnt
VIDEO_CARDS=
FLTK_DOCDIR=/usr/share/doc/fltk-1.3.3-r3/html
FCFLAGS=-O2 -pipe
PKGDIR=/usr/portage/packages
REPLACING_VERSIONS=2.10
HDEPEND=
PORTAGE_DEBUG=0
LLVM_TARGETS=
MAKEOPTS=-j8
INPUT_DEVICES=
ABI_X86=64
PORTAGE_TMPDIR=/var/tmp
USE_EXPAND_VALUES_USERLAND=BSD GNU
QEMU_USER_TARGETS=
NOCOLOR=true
LADSPA_PATH=/usr/lib64/ladspa
SUDO_UID=1000
COLUMNS=80
PYTHON_SINGLE_TARGET=
MAIL=/var/mail/root
CHOST=x86_64-pc-linux-gnu
PORTAGE_REPOSITORIES=[DEFAULT]
auto-sync = yes
main-repo = gentoo
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[chaoslab]
auto-sync = no
location = /var/lib/layman/chaoslab
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[didactic-duck]
auto-sync = no
location = /var/lib/layman/didactic-duck
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[gentoo]
auto-sync = yes
location = /usr/portage
masters =
priority = -1000
strict-misc-digests = true
sync-allow-hardlinks = true
sync-openpgp-key-path = /var/lib/gentoo/gkeys/keyrings/gentoo/release/pubring.gpg
sync-openpgp-key-refresh-retry-count = 40
sync-openpgp-key-refresh-retry-delay-exp-base = 2
sync-openpgp-key-refresh-retry-delay-max = 60
sync-openpgp-key-refresh-retry-delay-mult = 4
sync-openpgp-key-refresh-retry-overall-timeout = 1200
sync-rcu = false
sync-type = rsync
sync-uri = rsync://rsync.gentoo.org/gentoo-portage
sync-rsync-verify-max-age = 24
sync-rsync-verify-jobs = 1
sync-rsync-extra-opts =
sync-rsync-verify-metamanifest = no

[gentoo-zh]
auto-sync = no
location = /var/lib/layman/gentoo-zh
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[steam-overlay]
auto-sync = no
location = /var/lib/layman/steam-overlay
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

PORTAGE_IUSE=^(abi_x86_64|alpha|amd64|amd64\-fbsd|amd64\-linux|arm|arm64|elibc_AIX|elibc_Cygwin|elibc_Darwin|elibc_DragonFly|elibc_FreeBSD|elibc_HPUX|elibc_Interix|elibc_NetBSD|elibc_OpenBSD|elibc_SunOS|elibc_Winnt|elibc_bionic|elibc_glibc|elibc_mingw|elibc_mintlib|elibc_musl|elibc_uclibc|hppa|ia64|kernel_AIX|kernel_Darwin|kernel_FreeBSD|kernel_HPUX|kernel_NetBSD|kernel_OpenBSD|kernel_SunOS|kernel_Winnt|kernel_freemint|kernel_linux|m68k|m68k\-mint|mips|nls|ppc|ppc64|ppc64\-linux|ppc\-aix|ppc\-macos|prefix|prefix\-chain|prefix\-guest|s390|sh|sparc|sparc64\-solaris|sparc\-solaris|userland_BSD|userland_GNU|x64\-cygwin|x64\-macos|x64\-solaris|x86|x86\-cygwin|x86\-fbsd|x86\-linux|x86\-macos|x86\-solaris|x86\-winnt)$
PKGUSE=
QEMU_SOFTMMU_TARGETS=
ROOTPATH=/usr/x86_64-pc-linux-gnu/gcc-bin/6.4.0:/usr/lib/llvm/6/bin:/usr/lib/llvm/5/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin
PORTAGE_PYTHONPATH=/usr/lib64/python3.5/site-packages
KEYWORDS=~amd64 ~x86 ~amd64-linux ~x86-linux
LIBDIR_x32=libx32
SHELL=/bin/bash
TERM=xterm-256color
KERNEL=linux
PORTAGE_BASHRC_FILES=
PORTAGE_BIN_PATH=/usr/lib/portage/python3.5
LC_MESSAGES=C
EPREFIX=
ABI_MIPS=
PORTAGE_COMPRESSION_COMMAND=bzip2
TWISTED_DISABLE_WRITING_OF_PLUGIN_CACHE=1
CHOST_amd64=x86_64-pc-linux-gnu
CFLAGS_amd64=-m64
MONKEYD_PLUGINS=
PORTAGE_INTERNAL_CALLER=1
OPENMPI_RM=
USE_EXPAND_VALUES_ELIBC=AIX bionic Cygwin Darwin DragonFly FreeBSD glibc HPUX Interix mingw mintlib musl NetBSD OpenBSD SunOS uclibc Winnt
BOOTSTRAP_USE=cxx unicode internal-glib split-usr python_targets_python3_6 python_targets_python2_7 multilib
PORTDIR=/usr/portage
ELIBC=glibc
LDFLAGS_amd64=-m elf_x86_64
CFLAGS_x32=-mx32
LDFLAGS_x32=-m elf32_x86_64
SYSROOT=
CAMERAS=
MULTILIB_STRICT_DENY=64-bit.*shared object
RESUMECOMMAND_SSH=bash -c "x=\${2#ssh://} ; host=\${x%%/*} ; port=\${host##*:} ; host=\${host%:*} ; [[ \${host} = \${port} ]] && port= ; exec rsync --rsh=\"ssh \${port:+-p\${port}} \${3}\" -avP \"\${host}:/\${x#*/}\" \"\$1\"" rsync "${DISTDIR}/${FILE}" "${URI}" "${PORTAGE_SSH_OPTS}"
PYTHONDONTWRITEBYTECODE=1
PORTAGE_RESTRICT=
SHLVL=2
LANGUAGE=
LIBDIR_amd64=lib64
LICENSE=FDL-1.3 GPL-3
LDFLAGS_x86=-m elf_i386
FFTOOLS=
EBUILD=/usr/portage/app-misc/hello/hello-2.10.ebuild
FEATURES=assume-digests binpkg-logs config-protect-if-modified distlocks ebuild-locks fixlafiles merge-sync multilib-strict news parallel-fetch preserve-libs protect-owned sandbox sfperms strict unknown-features-warn unmerge-logs unmerge-orphans userfetch userpriv usersandbox usersync xattr
FFLAGS=-O2 -pipe
PORTAGE_IPC_DAEMON=1
FILESDIR=/var/tmp/portage/app-misc/hello-2.10/files
ACCEPT_LICENSE=FDL-1.3 GPL-3
WORKDIR=/var/tmp/portage/app-misc/hello-2.10/work
UWSGI_PLUGINS=
SYMLINK_LIB=yes
LOGNAME=root
CFLAGS_x86=-m32
PKG_TMPDIR=/var/tmp/portage/._unmerge_
NGINX_MODULES_HTTP=
EMERGE_FROM=ebuild
XAUTHORITY=/home/ppphp/.Xauthority
LDFLAGS=-Wl,-O1 -Wl,--as-needed
XTABLES_ADDONS=
PYTHON_TARGETS=
CHOST_x86=i686-pc-linux-gnu
RESTRICT=
IUSE_EFFECTIVE=abi_x86_64 alpha amd64 amd64-fbsd amd64-linux arm arm64 elibc_AIX elibc_Cygwin elibc_Darwin elibc_DragonFly elibc_FreeBSD elibc_HPUX elibc_Interix elibc_NetBSD elibc_OpenBSD elibc_SunOS elibc_Winnt elibc_bionic elibc_glibc elibc_mingw elibc_mintlib elibc_musl elibc_uclibc hppa ia64 kernel_AIX kernel_Darwin kernel_FreeBSD kernel_HPUX kernel_NetBSD kernel_OpenBSD kernel_SunOS kernel_Winnt kernel_freemint kernel_linux m68k m68k-mint mips nls ppc ppc-aix ppc-macos ppc64 ppc64-linux prefix prefix-chain prefix-guest s390 sh sparc sparc-solaris sparc64-solaris userland_BSD userland_GNU x64-cygwin x64-macos x64-solaris x86 x86-cygwin x86-fbsd x86-linux x86-macos x86-solaris x86-winnt
XDG_CONFIG_DIRS=/etc/xdg
PM_EBUILD_HOOK_DIR=/etc/portage/env
PATH=/usr/lib/portage/python3.5/ebuild-helpers/xattr:/usr/lib/portage/python3.5/ebuild-helpers:/usr/x86_64-pc-linux-gnu/gcc-bin/6.4.0:/usr/lib/llvm/6/bin:/usr/lib/llvm/5/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin
PROPERTIES=
DEFAULT_ABI=amd64
MULTILIB_STRICT_EXEMPT=(perl5|gcc|gcc-lib|binutils|eclipse-3|debug|portage|udev|systemd|clang|python-exec|llvm)
PORTAGE_LOG_FILE=/var/tmp/portage/app-misc/hello-2.10/temp/build.log
RPMDIR=/usr/portage/rpm
APACHE2_MPMS=
COLLECTD_PLUGINS=
ABI_S390=
NGINX_MODULES_STREAM=
PORTAGE_PYM_PATH=/usr/lib64/python3.5/site-packages
PROFILE_ONLY_VARIABLES=ARCH ELIBC IUSE_IMPLICIT KERNEL USERLAND USE_EXPAND_IMPLICIT USE_EXPAND_UNPREFIXED USE_EXPAND_VALUES_ARCH USE_EXPAND_VALUES_ELIBC USE_EXPAND_VALUES_KERNEL USE_EXPAND_VALUES_USERLAND
RUBY_TARGETS=
CVS_RSH=ssh
CHOST_x32=x86_64-pc-linux-gnux32
LESSOPEN=|lesspipe %s
EBUILD_PHASE_FUNC=pkg_setup
PORTAGE_BUILD_USER=portage
_=/usr/bin/printenv
`
}

func srcUnpack() string {
	return `
PVR=2.10
SANDBOX_DEBUG=0
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=01;05;37;41:mi=01;05;37;41:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.cfg=00;32:*.conf=00;32:*.diff=00;32:*.doc=00;32:*.ini=00;32:*.log=00;32:*.patch=00;32:*.pdf=00;32:*.ps=00;32:*.tex=00;32:*.txt=00;32:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
PORTAGE_BUILDDIR=/var/tmp/portage/app-misc/hello-2.10
PORTAGE_INST_UID=0
PKG_LOGDIR=/var/tmp/portage/app-misc/hello-2.10/temp/logging
DISTDIR=/var/tmp/portage/app-misc/hello-2.10/distdir
A=hello-2.10.tar.gz
D=/var/tmp/portage/app-misc/hello-2.10/image/
P=hello-2.10
T=/var/tmp/portage/app-misc/hello-2.10/temp
PORTAGE_INST_GID=0
LESS=-R -M --shift 5
DISPLAY=:0
CATEGORY=app-misc
PORTAGE_BASHRC=/etc/portage/bashrc
PORTAGE_COLORMAP=GOOD=$'[32;01m'
WARN=$'[33;01m'
BAD=$'[31;01m'
HILITE=$'[36m'
BRACKET=$'[34;01m'
NORMAL=$'[0m'
BUILD_PREFIX=/var/tmp/portage
SANDBOX_DEBUG_LOG=/var/log/sandbox/sandbox-debug-31649.log
COLORTERM=truecolor
USE=abi_x86_64 amd64 elibc_glibc kernel_linux nls userland_GNU
PORTAGE_REPO_NAME=gentoo
ED=/var/tmp/portage/app-misc/hello-2.10/image/
SANDBOX_LOG=/var/log/sandbox/sandbox-31649.log
PORTAGE_DEPCACHEDIR=/var/cache/edb/dep
PORTAGE_BZIP2_COMMAND=bzip2
PORTAGE_PYTHON=/usr/bin/python3.5m
MERGE_TYPE=source
EROOT=/
USE_EXPAND=ABI_MIPS ABI_PPC ABI_S390 ABI_X86 ALSA_CARDS APACHE2_MODULES APACHE2_MPMS CALLIGRA_FEATURES CAMERAS COLLECTD_PLUGINS CPU_FLAGS_ARM CPU_FLAGS_X86 CURL_SSL ELIBC ENLIGHTENMENT_MODULES FFTOOLS GPSD_PROTOCOLS GRUB_PLATFORMS INPUT_DEVICES KERNEL L10N LCD_DEVICES LIBREOFFICE_EXTENSIONS LIRC_DEVICES LLVM_TARGETS MONKEYD_PLUGINS NETBEANS_MODULES NGINX_MODULES_HTTP NGINX_MODULES_MAIL NGINX_MODULES_STREAM OFED_DRIVERS OFFICE_IMPLEMENTATION OPENMPI_FABRICS OPENMPI_OFED_FEATURES OPENMPI_RM PHP_TARGETS POSTGRES_TARGETS PYTHON_SINGLE_TARGET PYTHON_TARGETS QEMU_SOFTMMU_TARGETS QEMU_USER_TARGETS ROS_MESSAGES RUBY_TARGETS SANE_BACKENDS USERLAND UWSGI_PLUGINS VIDEO_CARDS VOICEMAIL_STORAGE XFCE_PLUGINS XTABLES_ADDONS
EAPI=6
LC_COLLATE=C
PORTAGE_OVERRIDE_EPREFIX=
EBUILD_PHASE=unpack
ROOT=/
PORTAGE_XATTR_EXCLUDE=btrfs.* security.evm security.ima 	security.selinux system.nfs4_acl user.apache_handler 	user.Beagle.* user.dublincore.* user.mime_encoding user.xdg.*
PORTAGE_COMPRESS_EXCLUDE_SUFFIXES=css gif htm[l]? jp[e]?g js pdf png
PORTAGE_BUILD_GROUP=portage
PORTAGE_CONFIGROOT=/
PWD=/home/ppphp
PR=r0
SANDBOX_ON=1
PORTAGE_ACTUAL_DISTDIR=/usr/portage/distfiles
PV=2.10
HOME=/var/tmp/portage/app-misc/hello-2.10/homedir
PF=hello-2.10
PORTAGE_SIGPIPE_STATUS=141
PN=hello
PORTAGE_GID=250
BASH_ENV=/usr/share/sandbox/sandbox.bashrc
PORTAGE_ECLASS_LOCATIONS=/usr/portage
PORTAGE_WORKDIR_MODE=0700
PORTAGE_FEATURES=assume-digests binpkg-logs config-protect-if-modified distlocks ebuild-locks fixlafiles merge-sync multilib-strict news parallel-fetch preserve-libs protect-owned sandbox sfperms strict unknown-features-warn unmerge-logs unmerge-orphans userfetch userpriv usersandbox usersync xattr
ECLASSDIR=/usr/portage/eclass
PORTAGE_ARCHLIST=alpha amd64 amd64-fbsd amd64-linux arm arm-linux arm64 arm64-linux hppa ia64 m68k m68k-mint mips ppc ppc-aix ppc-macos ppc64 ppc64-linux s390 sh sparc sparc-solaris sparc64-solaris x64-cygwin x64-macos x64-solaris x86 x86-cygwin x86-fbsd x86-linux x86-macos x86-solaris x86-winnt
PKGDIR=/usr/portage/packages
SANDBOX_READ=/
PORTAGE_DEBUG=0
TMPDIR=/tmp
SANDBOX_ACTIVE=armedandready
PORTAGE_TMPDIR=/var/tmp
NOCOLOR=true
COLUMNS=80
PORTAGE_REPOSITORIES=[DEFAULT]
auto-sync = yes
main-repo = gentoo
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[chaoslab]
auto-sync = no
location = /var/lib/layman/chaoslab
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[didactic-duck]
auto-sync = no
location = /var/lib/layman/didactic-duck
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[gentoo]
auto-sync = yes
location = /usr/portage
masters = 
priority = -1000
strict-misc-digests = true
sync-allow-hardlinks = true
sync-openpgp-key-path = /var/lib/gentoo/gkeys/keyrings/gentoo/release/pubring.gpg
sync-openpgp-key-refresh-retry-count = 40
sync-openpgp-key-refresh-retry-delay-exp-base = 2
sync-openpgp-key-refresh-retry-delay-max = 60
sync-openpgp-key-refresh-retry-delay-mult = 4
sync-openpgp-key-refresh-retry-overall-timeout = 1200
sync-rcu = false
sync-type = rsync
sync-uri = rsync://rsync.gentoo.org/gentoo-portage
sync-rsync-verify-max-age = 24
sync-rsync-verify-jobs = 1
sync-rsync-extra-opts = 
sync-rsync-verify-metamanifest = no

[gentoo-zh]
auto-sync = no
location = /var/lib/layman/gentoo-zh
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[steam-overlay]
auto-sync = no
location = /var/lib/layman/steam-overlay
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

PKGUSE=
PORTAGE_IUSE=^(abi_x86_64|alpha|amd64|amd64\-fbsd|amd64\-linux|arm|arm64|elibc_AIX|elibc_Cygwin|elibc_Darwin|elibc_DragonFly|elibc_FreeBSD|elibc_HPUX|elibc_Interix|elibc_NetBSD|elibc_OpenBSD|elibc_SunOS|elibc_Winnt|elibc_bionic|elibc_glibc|elibc_mingw|elibc_mintlib|elibc_musl|elibc_uclibc|hppa|ia64|kernel_AIX|kernel_Darwin|kernel_FreeBSD|kernel_HPUX|kernel_NetBSD|kernel_OpenBSD|kernel_SunOS|kernel_Winnt|kernel_freemint|kernel_linux|m68k|m68k\-mint|mips|nls|ppc|ppc64|ppc64\-linux|ppc\-aix|ppc\-macos|prefix|prefix\-chain|prefix\-guest|s390|sh|sparc|sparc64\-solaris|sparc\-solaris|userland_BSD|userland_GNU|x64\-cygwin|x64\-macos|x64\-solaris|x86|x86\-cygwin|x86\-fbsd|x86\-linux|x86\-macos|x86\-solaris|x86\-winnt)$
ROOTPATH=/usr/x86_64-pc-linux-gnu/gcc-bin/6.4.0:/usr/lib/llvm/6/bin:/usr/lib/llvm/5/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin
PORTAGE_PYTHONPATH=/usr/lib64/python3.5/site-packages
TERM=xterm-256color
PORTAGE_BASHRC_FILES=
SANDBOX_PREDICT=/var/tmp/portage/app-misc/hello-2.10/homedir:/dev/crypto:/proc/self/coredump_filter:/var/cache/fontconfig
PORTAGE_BIN_PATH=/usr/lib/portage/python3.5
LC_MESSAGES=C
EPREFIX=
SANDBOX_MESSAGE_P@TH=/proc/31649/fd/2
PORTAGE_COMPRESSION_COMMAND=bzip2
PORTAGE_INTERNAL_CALLER=1
PORTDIR=/usr/portage
SANDBOX_BASHRC=/usr/share/sandbox/sandbox.bashrc
SYSROOT=
PYTHONDONTWRITEBYTECODE=1
PORTAGE_RESTRICT=
SHLVL=2
EBUILD=/usr/portage/app-misc/hello/hello-2.10.ebuild
FEATURES=assume-digests binpkg-logs config-protect-if-modified distlocks ebuild-locks fixlafiles merge-sync multilib-strict news parallel-fetch preserve-libs protect-owned sandbox sfperms strict unknown-features-warn unmerge-logs unmerge-orphans userfetch userpriv usersandbox usersync xattr
PORTAGE_IPC_DAEMON=1
FILESDIR=/var/tmp/portage/app-misc/hello-2.10/files
ACCEPT_LICENSE=FDL-1.3 GPL-3
WORKDIR=/var/tmp/portage/app-misc/hello-2.10/work
SANDBOX_VERBOSE=1
LOGNAME=portage
PKG_TMPDIR=/var/tmp/portage/._unmerge_
EMERGE_FROM=ebuild
XAUTHORITY=/home/ppphp/.Xauthority
SANDBOX_LIB=libsandbox.so
SANDBOX_WRITE=/dev/fd:/proc/self/fd:/dev/zero:/dev/null:/dev/full:/dev/console:/dev/tty:/dev/vc/:/dev/pty:/dev/tts:/dev/ptmx:/dev/pts/:/dev/shm:/tmp/:/var/tmp/:/var/tmp/portage/app-misc/hello-2.10/homedir/.bash_history::/usr/tmp/conftest:/usr/lib/conftest:/usr/lib32/conftest:/usr/lib64/conftest:/usr/tmp/cf:/usr/lib/cf:/usr/lib32/cf:/usr/lib64/cf
PM_EBUILD_HOOK_DIR=/etc/portage/env
PATH=/usr/lib/portage/python3.5/ebuild-helpers/xattr:/usr/lib/portage/python3.5/ebuild-helpers:/usr/x86_64-pc-linux-gnu/gcc-bin/6.4.0:/usr/lib/llvm/6/bin:/usr/lib/llvm/5/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin
PORTAGE_LOG_FILE=/var/tmp/portage/app-misc/hello-2.10/temp/build.log
LD_PRELOAD=libsandbox.so
PORTAGE_PYM_PATH=/usr/lib64/python3.5/site-packages
CVS_RSH=ssh
LESSOPEN=|lesspipe %s
EBUILD_PHASE_FUNC=src_unpack
PORTAGE_BUILD_USER=portage
_=/usr/bin/printenv
`
}

func srcPrepare() string {
	return `
PVR=2.10
SANDBOX_DEBUG=0
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=01;05;37;41:mi=01;05;37;41:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.cfg=00;32:*.conf=00;32:*.diff=00;32:*.doc=00;32:*.ini=00;32:*.log=00;32:*.patch=00;32:*.pdf=00;32:*.ps=00;32:*.tex=00;32:*.txt=00;32:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
PORTAGE_BUILDDIR=/var/tmp/portage/app-misc/hello-2.10
PORTAGE_INST_UID=0
PKG_LOGDIR=/var/tmp/portage/app-misc/hello-2.10/temp/logging
DISTDIR=/var/tmp/portage/app-misc/hello-2.10/distdir
A=hello-2.10.tar.gz
D=/var/tmp/portage/app-misc/hello-2.10/image/
P=hello-2.10
T=/var/tmp/portage/app-misc/hello-2.10/temp
PORTAGE_INST_GID=0
LESS=-R -M --shift 5
DISPLAY=:0
CATEGORY=app-misc
PORTAGE_BASHRC=/etc/portage/bashrc
PORTAGE_COLORMAP=GOOD=$'^[[32;01m'
WARN=$'^[[33;01m'
BAD=$'^[[31;01m'
HILITE=$'^[[36m'
BRACKET=$'^[[34;01m'
NORMAL=$'^[[0m'
BUILD_PREFIX=/var/tmp/portage
SANDBOX_DEBUG_LOG=/var/log/sandbox/sandbox-debug-13258.log
COLORTERM=truecolor
USE=abi_x86_64 amd64 elibc_glibc kernel_linux nls userland_GNU
PORTAGE_REPO_NAME=gentoo
ED=/var/tmp/portage/app-misc/hello-2.10/image/
SANDBOX_LOG=/var/log/sandbox/sandbox-13258.log
PORTAGE_DEPCACHEDIR=/var/cache/edb/dep
PORTAGE_BZIP2_COMMAND=bzip2
PORTAGE_PYTHON=/usr/bin/python3.5m
MERGE_TYPE=source
EROOT=/
USE_EXPAND=ABI_MIPS ABI_PPC ABI_S390 ABI_X86 ALSA_CARDS APACHE2_MODULES APACHE2_MPMS CALLIGRA_FEATURES CAMERAS COLLECTD_PLUGINS CPU_FLAGS_ARM CPU_FLAGS_X86 CURL_SSL ELIBC ENLIGHTENMENT_MODULES FFTOOLS GPSD_PROTOCOLS GRUB_PLATFORMS INPUT_DEVICES KERNEL L10N LCD_DEVICES LIBREOFFICE_EXTENSIONS LIRC_DEVICES LLVM_TARGETS MONKEYD_PLUGINS NETBEANS_MODULES NGINX_MODULES_HTTP NGINX_MODULES_MAIL NGINX_MODULES_STREAM OFED_DRIVERS OFFICE_IMPLEMENTATION OPENMPI_FABRICS OPENMPI_OFED_FEATURES OPENMPI_RM PHP_TARGETS POSTGRES_TARGETS PYTHON_SINGLE_TARGET PYTHON_TARGETS QEMU_SOFTMMU_TARGETS QEMU_USER_TARGETS ROS_MESSAGES RUBY_TARGETS SANE_BACKENDS USERLAND UWSGI_PLUGINS VIDEO_CARDS VOICEMAIL_STORAGE XFCE_PLUGINS XTABLES_ADDONS
EAPI=6
LC_COLLATE=C
PORTAGE_OVERRIDE_EPREFIX=
EBUILD_PHASE=prepare
ROOT=/
PORTAGE_XATTR_EXCLUDE=btrfs.* security.evm security.ima         security.selinux system.nfs4_acl user.apache_handler    user.Beagle.* user.dublincore.* user.mime_encoding user.xdg.*
PORTAGE_COMPRESS_EXCLUDE_SUFFIXES=css gif htm[l]? jp[e]?g js pdf png
PORTAGE_BUILD_GROUP=portage
PORTAGE_CONFIGROOT=/
PWD=/home/ppphp
PR=r0
SANDBOX_ON=1
PORTAGE_ACTUAL_DISTDIR=/usr/portage/distfiles
PV=2.10
HOME=/var/tmp/portage/app-misc/hello-2.10/homedir
PF=hello-2.10
PORTAGE_SIGPIPE_STATUS=141
PN=hello
PORTAGE_GID=250
BASH_ENV=/usr/share/sandbox/sandbox.bashrc
PORTAGE_ECLASS_LOCATIONS=/usr/portage
PORTAGE_WORKDIR_MODE=0700
PORTAGE_FEATURES=assume-digests binpkg-logs config-protect-if-modified distlocks ebuild-locks fixlafiles merge-sync multilib-strict news parallel-fetch preserve-libs protect-owned sandbox sfperms strict unknown-features-warn unmerge-logs unmerge-orphans userfetch userpriv usersandbox usersync xattr
ECLASSDIR=/usr/portage/eclass
PORTAGE_ARCHLIST=alpha amd64 amd64-fbsd amd64-linux arm arm-linux arm64 arm64-linux hppa ia64 m68k m68k-mint mips ppc ppc-aix ppc-macos ppc64 ppc64-linux s390 sh sparc sparc-solaris sparc64-solaris x64-cygwin x64-macos x64-solaris x86 x86-cygwin x86-fbsd x86-linux x86-macos x86-solaris x86-winnt
PKGDIR=/usr/portage/packages
SANDBOX_READ=/
PORTAGE_DEBUG=0
TMPDIR=/tmp
SANDBOX_ACTIVE=armedandready
PORTAGE_TMPDIR=/var/tmp
NOCOLOR=true
COLUMNS=80
PORTAGE_REPOSITORIES=[DEFAULT]
auto-sync = yes
main-repo = gentoo
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[chaoslab]
auto-sync = no
location = /var/lib/layman/chaoslab
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[didactic-duck]
auto-sync = no
location = /var/lib/layman/didactic-duck
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[gentoo]
auto-sync = yes
location = /usr/portage
masters =
priority = -1000
strict-misc-digests = true
sync-allow-hardlinks = true
sync-openpgp-key-path = /var/lib/gentoo/gkeys/keyrings/gentoo/release/pubring.gpg
sync-openpgp-key-refresh-retry-count = 40
sync-openpgp-key-refresh-retry-delay-exp-base = 2
sync-openpgp-key-refresh-retry-delay-max = 60
sync-openpgp-key-refresh-retry-delay-mult = 4
sync-openpgp-key-refresh-retry-overall-timeout = 1200
sync-rcu = false
sync-type = rsync
sync-uri = rsync://rsync.gentoo.org/gentoo-portage
sync-rsync-verify-max-age = 24
sync-rsync-verify-jobs = 1
sync-rsync-extra-opts =
sync-rsync-verify-metamanifest = no

[gentoo-zh]
auto-sync = no
location = /var/lib/layman/gentoo-zh
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[steam-overlay]
auto-sync = no
location = /var/lib/layman/steam-overlay
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

PORTAGE_IUSE=^(abi_x86_64|alpha|amd64|amd64\-fbsd|amd64\-linux|arm|arm64|elibc_AIX|elibc_Cygwin|elibc_Darwin|elibc_DragonFly|elibc_FreeBSD|elibc_HPUX|elibc_Interix|elibc_NetBSD|elibc_OpenBSD|elibc_SunOS|elibc_Winnt|elibc_bionic|elibc_glibc|elibc_mingw|elibc_mintlib|elibc_musl|elibc_uclibc|hppa|ia64|kernel_AIX|kernel_Darwin|kernel_FreeBSD|kernel_HPUX|kernel_NetBSD|kernel_OpenBSD|kernel_SunOS|kernel_Winnt|kernel_freemint|kernel_linux|m68k|m68k\-mint|mips|nls|ppc|ppc64|ppc64\-linux|ppc\-aix|ppc\-macos|prefix|prefix\-chain|prefix\-guest|s390|sh|sparc|sparc64\-solaris|sparc\-solaris|userland_BSD|userland_GNU|x64\-cygwin|x64\-macos|x64\-solaris|x86|x86\-cygwin|x86\-fbsd|x86\-linux|x86\-macos|x86\-solaris|x86\-winnt)$
PKGUSE=
ROOTPATH=/usr/x86_64-pc-linux-gnu/gcc-bin/6.4.0:/usr/lib/llvm/6/bin:/usr/lib/llvm/5/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin
PORTAGE_PYTHONPATH=/usr/lib64/python3.5/site-packages
TERM=xterm-256color
PORTAGE_BASHRC_FILES=
SANDBOX_PREDICT=/var/tmp/portage/app-misc/hello-2.10/homedir:/dev/crypto:/proc/self/coredump_filter:/var/cache/fontconfig
PORTAGE_BIN_PATH=/usr/lib/portage/python3.5
LC_MESSAGES=C
EPREFIX=
SANDBOX_MESSAGE_P@TH=/proc/13258/fd/2
PORTAGE_COMPRESSION_COMMAND=bzip2
PORTAGE_INTERNAL_CALLER=1
PORTDIR=/usr/portage
SANDBOX_BASHRC=/usr/share/sandbox/sandbox.bashrc
SYSROOT=
PYTHONDONTWRITEBYTECODE=1
PORTAGE_RESTRICT=
SHLVL=2
EBUILD=/usr/portage/app-misc/hello/hello-2.10.ebuild
FEATURES=assume-digests binpkg-logs config-protect-if-modified distlocks ebuild-locks fixlafiles merge-sync multilib-strict news parallel-fetch preserve-libs protect-owned sandbox sfperms strict unknown-features-warn unmerge-logs unmerge-orphans userfetch userpriv usersandbox usersync xattr
PORTAGE_IPC_DAEMON=1
FILESDIR=/var/tmp/portage/app-misc/hello-2.10/files
ACCEPT_LICENSE=FDL-1.3 GPL-3
WORKDIR=/var/tmp/portage/app-misc/hello-2.10/work
SANDBOX_VERBOSE=1
LOGNAME=portage
PKG_TMPDIR=/var/tmp/portage/._unmerge_
EMERGE_FROM=ebuild
XAUTHORITY=/home/ppphp/.Xauthority
SANDBOX_LIB=libsandbox.so
SANDBOX_WRITE=/dev/fd:/proc/self/fd:/dev/zero:/dev/null:/dev/full:/dev/console:/dev/tty:/dev/vc/:/dev/pty:/dev/tts:/dev/ptmx:/dev/pts/:/dev/shm:/tmp/:/var/tmp/:/var/tmp/portage/app-misc/hello-2.10/homedir/.bash_history::/usr/tmp/conftest:/usr/lib/conftest:/usr/lib32/conftest:/usr/lib64/conftest:/usr/tmp/cf:/usr/lib/cf:/usr/lib32/cf:/usr/lib64/cf
PM_EBUILD_HOOK_DIR=/etc/portage/env
PATH=/usr/lib/portage/python3.5/ebuild-helpers/xattr:/usr/lib/portage/python3.5/ebuild-helpers:/usr/x86_64-pc-linux-gnu/gcc-bin/6.4.0:/usr/lib/llvm/6/bin:/usr/lib/llvm/5/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin
PORTAGE_LOG_FILE=/var/tmp/portage/app-misc/hello-2.10/temp/build.log
LD_PRELOAD=libsandbox.so
PORTAGE_PYM_PATH=/usr/lib64/python3.5/site-packages
CVS_RSH=ssh
LESSOPEN=|lesspipe %s
EBUILD_PHASE_FUNC=src_prepare
PORTAGE_BUILD_USER=portage
_=/usr/bin/printenv
`
}

func srcConfigure() string {
	return `
PVR=2.10
SANDBOX_DEBUG=0
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=01;05;37;41:mi=01;05;37;41:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.cfg=00;32:*.conf=00;32:*.diff=00;32:*.doc=00;32:*.ini=00;32:*.log=00;32:*.patch=00;32:*.pdf=00;32:*.ps=00;32:*.tex=00;32:*.txt=00;32:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
PORTAGE_BUILDDIR=/var/tmp/portage/app-misc/hello-2.10
PORTAGE_INST_UID=0
PKG_LOGDIR=/var/tmp/portage/app-misc/hello-2.10/temp/logging
DISTDIR=/var/tmp/portage/app-misc/hello-2.10/distdir
A=hello-2.10.tar.gz
D=/var/tmp/portage/app-misc/hello-2.10/image/
P=hello-2.10
T=/var/tmp/portage/app-misc/hello-2.10/temp
PORTAGE_INST_GID=0
LESS=-R -M --shift 5
DISPLAY=:0
CATEGORY=app-misc
PORTAGE_BASHRC=/etc/portage/bashrc
PORTAGE_COLORMAP=GOOD=$'^[[32;01m'
WARN=$'^[[33;01m'
BAD=$'^[[31;01m'
HILITE=$'^[[36m'
BRACKET=$'^[[34;01m'
NORMAL=$'^[[0m'
BUILD_PREFIX=/var/tmp/portage
SANDBOX_DEBUG_LOG=/var/log/sandbox/sandbox-debug-13294.log
COLORTERM=truecolor
USE=abi_x86_64 amd64 elibc_glibc kernel_linux nls userland_GNU
PORTAGE_REPO_NAME=gentoo
ED=/var/tmp/portage/app-misc/hello-2.10/image/
SANDBOX_LOG=/var/log/sandbox/sandbox-13294.log
PORTAGE_DEPCACHEDIR=/var/cache/edb/dep
PORTAGE_BZIP2_COMMAND=bzip2
PORTAGE_PYTHON=/usr/bin/python3.5m
MERGE_TYPE=source
EROOT=/
USE_EXPAND=ABI_MIPS ABI_PPC ABI_S390 ABI_X86 ALSA_CARDS APACHE2_MODULES APACHE2_MPMS CALLIGRA_FEATURES CAMERAS COLLECTD_PLUGINS CPU_FLAGS_ARM CPU_FLAGS_X86 CURL_SSL ELIBC ENLIGHTENMENT_MODULES FFTOOLS GPSD_PROTOCOLS GRUB_PLATFORMS INPUT_DEVICES KERNEL L10N LCD_DEVICES LIBREOFFICE_EXTENSIONS LIRC_DEVICES LLVM_TARGETS MONKEYD_PLUGINS NETBEANS_MODULES NGINX_MODULES_HTTP NGINX_MODULES_MAIL NGINX_MODULES_STREAM OFED_DRIVERS OFFICE_IMPLEMENTATION OPENMPI_FABRICS OPENMPI_OFED_FEATURES OPENMPI_RM PHP_TARGETS POSTGRES_TARGETS PYTHON_SINGLE_TARGET PYTHON_TARGETS QEMU_SOFTMMU_TARGETS QEMU_USER_TARGETS ROS_MESSAGES RUBY_TARGETS SANE_BACKENDS USERLAND UWSGI_PLUGINS VIDEO_CARDS VOICEMAIL_STORAGE XFCE_PLUGINS XTABLES_ADDONS
EAPI=6
LC_COLLATE=C
PORTAGE_OVERRIDE_EPREFIX=
EBUILD_PHASE=configure
ROOT=/
PORTAGE_XATTR_EXCLUDE=btrfs.* security.evm security.ima         security.selinux system.nfs4_acl user.apache_handler    user.Beagle.* user.dublincore.* user.mime_encoding user.xdg.*
PORTAGE_COMPRESS_EXCLUDE_SUFFIXES=css gif htm[l]? jp[e]?g js pdf png
PORTAGE_BUILD_GROUP=portage
PORTAGE_CONFIGROOT=/
PWD=/home/ppphp
PR=r0
SANDBOX_ON=1
PORTAGE_ACTUAL_DISTDIR=/usr/portage/distfiles
PV=2.10
HOME=/var/tmp/portage/app-misc/hello-2.10/homedir
PF=hello-2.10
PORTAGE_SIGPIPE_STATUS=141
PN=hello
PORTAGE_GID=250
BASH_ENV=/usr/share/sandbox/sandbox.bashrc
PORTAGE_ECLASS_LOCATIONS=/usr/portage
PORTAGE_WORKDIR_MODE=0700
PORTAGE_FEATURES=assume-digests binpkg-logs config-protect-if-modified distlocks ebuild-locks fixlafiles merge-sync multilib-strict news parallel-fetch preserve-libs protect-owned sandbox sfperms strict unknown-features-warn unmerge-logs unmerge-orphans userfetch userpriv usersandbox usersync xattr
ECLASSDIR=/usr/portage/eclass
PORTAGE_ARCHLIST=alpha amd64 amd64-fbsd amd64-linux arm arm-linux arm64 arm64-linux hppa ia64 m68k m68k-mint mips ppc ppc-aix ppc-macos ppc64 ppc64-linux s390 sh sparc sparc-solaris sparc64-solaris x64-cygwin x64-macos x64-solaris x86 x86-cygwin x86-fbsd x86-linux x86-macos x86-solaris x86-winnt
PKGDIR=/usr/portage/packages
SANDBOX_READ=/
PORTAGE_DEBUG=0
TMPDIR=/tmp
SANDBOX_ACTIVE=armedandready
PORTAGE_TMPDIR=/var/tmp
NOCOLOR=true
COLUMNS=80
PORTAGE_REPOSITORIES=[DEFAULT]
auto-sync = yes
main-repo = gentoo
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[chaoslab]
auto-sync = no
location = /var/lib/layman/chaoslab
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[didactic-duck]
auto-sync = no
location = /var/lib/layman/didactic-duck
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[gentoo]
auto-sync = yes
location = /usr/portage
masters =
priority = -1000
strict-misc-digests = true
sync-allow-hardlinks = true
sync-openpgp-key-path = /var/lib/gentoo/gkeys/keyrings/gentoo/release/pubring.gpg
sync-openpgp-key-refresh-retry-count = 40
sync-openpgp-key-refresh-retry-delay-exp-base = 2
sync-openpgp-key-refresh-retry-delay-max = 60
sync-openpgp-key-refresh-retry-delay-mult = 4
sync-openpgp-key-refresh-retry-overall-timeout = 1200
sync-rcu = false
sync-type = rsync
sync-uri = rsync://rsync.gentoo.org/gentoo-portage
sync-rsync-verify-max-age = 24
sync-rsync-verify-jobs = 1
sync-rsync-extra-opts =
sync-rsync-verify-metamanifest = no

[gentoo-zh]
auto-sync = no
location = /var/lib/layman/gentoo-zh
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

[steam-overlay]
auto-sync = no
location = /var/lib/layman/steam-overlay
masters = gentoo
priority = 50
strict-misc-digests = true
sync-allow-hardlinks = true
sync-rcu = false

PORTAGE_IUSE=^(abi_x86_64|alpha|amd64|amd64\-fbsd|amd64\-linux|arm|arm64|elibc_AIX|elibc_Cygwin|elibc_Darwin|elibc_DragonFly|elibc_FreeBSD|elibc_HPUX|elibc_Interix|elibc_NetBSD|elibc_OpenBSD|elibc_SunOS|elibc_Winnt|elibc_bionic|elibc_glibc|elibc_mingw|elibc_mintlib|elibc_musl|elibc_uclibc|hppa|ia64|kernel_AIX|kernel_Darwin|kernel_FreeBSD|kernel_HPUX|kernel_NetBSD|kernel_OpenBSD|kernel_SunOS|kernel_Winnt|kernel_freemint|kernel_linux|m68k|m68k\-mint|mips|nls|ppc|ppc64|ppc64\-linux|ppc\-aix|ppc\-macos|prefix|prefix\-chain|prefix\-guest|s390|sh|sparc|sparc64\-solaris|sparc\-solaris|userland_BSD|userland_GNU|x64\-cygwin|x64\-macos|x64\-solaris|x86|x86\-cygwin|x86\-fbsd|x86\-linux|x86\-macos|x86\-solaris|x86\-winnt)$
PKGUSE=
ROOTPATH=/usr/x86_64-pc-linux-gnu/gcc-bin/6.4.0:/usr/lib/llvm/6/bin:/usr/lib/llvm/5/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin
PORTAGE_PYTHONPATH=/usr/lib64/python3.5/site-packages
TERM=xterm-256color
PORTAGE_BASHRC_FILES=
SANDBOX_PREDICT=/var/tmp/portage/app-misc/hello-2.10/homedir:/dev/crypto:/proc/self/coredump_filter:/var/cache/fontconfig
PORTAGE_BIN_PATH=/usr/lib/portage/python3.5
LC_MESSAGES=C
EPREFIX=
SANDBOX_MESSAGE_P@TH=/proc/13294/fd/2
PORTAGE_COMPRESSION_COMMAND=bzip2
PORTAGE_INTERNAL_CALLER=1
PORTDIR=/usr/portage
SANDBOX_BASHRC=/usr/share/sandbox/sandbox.bashrc
SYSROOT=
PYTHONDONTWRITEBYTECODE=1
PORTAGE_RESTRICT=
SHLVL=2
EBUILD=/usr/portage/app-misc/hello/hello-2.10.ebuild
FEATURES=assume-digests binpkg-logs config-protect-if-modified distlocks ebuild-locks fixlafiles merge-sync multilib-strict news parallel-fetch preserve-libs protect-owned sandbox sfperms strict unknown-features-warn unmerge-logs unmerge-orphans userfetch userpriv usersandbox usersync xattr
PORTAGE_IPC_DAEMON=1
FILESDIR=/var/tmp/portage/app-misc/hello-2.10/files
ACCEPT_LICENSE=FDL-1.3 GPL-3
WORKDIR=/var/tmp/portage/app-misc/hello-2.10/work
SANDBOX_VERBOSE=1
LOGNAME=portage
PKG_TMPDIR=/var/tmp/portage/._unmerge_
EMERGE_FROM=ebuild
XAUTHORITY=/home/ppphp/.Xauthority
SANDBOX_LIB=libsandbox.so
SANDBOX_WRITE=/dev/fd:/proc/self/fd:/dev/zero:/dev/null:/dev/full:/dev/console:/dev/tty:/dev/vc/:/dev/pty:/dev/tts:/dev/ptmx:/dev/pts/:/dev/shm:/tmp/:/var/tmp/:/var/tmp/portage/app-misc/hello-2.10/homedir/.bash_history::/usr/tmp/conftest:/usr/lib/conftest:/usr/lib32/conftest:/usr/lib64/conftest:/usr/tmp/cf:/usr/lib/cf:/usr/lib32/cf:/usr/lib64/cf
PM_EBUILD_HOOK_DIR=/etc/portage/env
PATH=/usr/lib/portage/python3.5/ebuild-helpers/xattr:/usr/lib/portage/python3.5/ebuild-helpers:/usr/x86_64-pc-linux-gnu/gcc-bin/6.4.0:/usr/lib/llvm/6/bin:/usr/lib/llvm/5/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin
PORTAGE_LOG_FILE=/var/tmp/portage/app-misc/hello-2.10/temp/build.log
LD_PRELOAD=libsandbox.so
PORTAGE_PYM_PATH=/usr/lib64/python3.5/site-packages
CVS_RSH=ssh
LESSOPEN=|lesspipe %s
EBUILD_PHASE_FUNC=src_configure
PORTAGE_BUILD_USER=portage
_=/usr/bin/printenv
`
}

func srcCompile() {

}

func srcTest() {

}

func srcInstall() {

}

func pkgPreInst() {

}

func pkgPostInst() {

}

func pkgPreRm() {

}

func pkgPostRm() {

}

func pkgConfig() {

}

func pkgInfo() {

}
