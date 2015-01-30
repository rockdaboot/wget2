# got some hints from https://gitorious.org/openismus-playground/examplelib/source

if HAVE_PO
SUBDIRS = po
else
SUBDIRS =
endif

SUBDIRS += include libmget src data examples $(LIBMGET_DOCS) tests

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

# Enable GTK-Doc during make distcheck
#DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc --enable-man

## Install the generated pkg-config file (.pc) into the expected location for
## architecture-dependent package configuration information. Occasionally,
## pkg-config files are also used for architecture-independent data packages,
## in which case the correct install location would be $(datadir)/pkgconfig.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libmget-$(LIBMGET_API_VERSION).pc

EXTRA_DIST = config.rpath
