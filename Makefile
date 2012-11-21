# Package-related substitution variables
export package     = mget
export version     = 0.1.2
export tarname     = $(package)
export distdir     = $(tarname)-$(version)

# Prefix-related substitution variables
export prefix      = /usr/local
export exec_prefix = $(prefix)
export bindir      = $(prefix)/bin

# Tool-related substitution variables
# -Wstack-protector -Wconversion
#CC=$(SILENT)CCC_CC=clang /usr/share/clang/scan-build/ccc-analyzer -fblocks
#CC=$(SILENT)clang -fblocks
export CC = $(SILENT)gcc
export CFLAGS = -g -std=gnu99 -pedantic -fPIC\
 -Wall -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes\
 -Wwrite-strings -Wformat=2 -Wformat -Wformat-security\
 -fstack-protector --param ssp-buffer-size=4\
 -Wno-sign-compare -Wextra -D_FORTIFY_SOURCE=2\
 -Wundef -Wcast-align -O2 \
 -D _FILE_OFFSET_BITS=64\
 -D ENABLE_NLS=1\
 -D LOCALEDIR=\"/usr/share/locale\"
# -D GLOBAL_CONFIG_FILE=\"/etc/mgetrc\"

#LN=$(SILENT)gcc -fPIE -pie -Wl,-z,relro,-z,now
export LDFLAGS = $(SILENT)gcc -fPIE -pie -Wl,-z,relro,--as-needed

all:
	@SILENT="@" $(MAKE) -C src --no-print-directory $@
	@SILENT="@" $(MAKE) -C tests --no-print-directory $@

verbose:
	@SILENT="" $(MAKE) -C src --no-print-directory $@
	@SILENT="" $(MAKE) -C tests --no-print-directory $@

analyze install:
	@$(MAKE) -C src $@

check:
	@$(MAKE) -C tests $@
	@echo "*** ALL TESTS PASSED ***"

clean:
	@echo Removing objects and binaries...
	@$(MAKE) -C src $@
	@$(MAKE) -C tests $@

dist: $(distdir).tar.gz

$(distdir).tar.gz: FORCE $(distdir)
	tar chof - $(distdir) | gzip -9 -c >$(distdir).tar.gz
	rm -rf $(distdir)

$(distdir):
	mkdir -p $(distdir)/src
	cp Makefile $(distdir)
	cp src/Makefile $(distdir)/src
	cp src/*.c src/*.h $(distdir)/src

distcheck: $(distdir).tar.gz
	gzip -cd $+ | tar xvf -
	$(MAKE) -C $(distdir) all check
	$(MAKE) -C $(distdir) DESTDIR=$${PWD}/$(distdir)/_inst install uninstall
	$(MAKE) -C $(distdir) clean
	rm -rf $(distdir)
	@echo "*** Package $(distdir).tar.gz ready for distribution."

FORCE:
	-rm $(distdir).tar.gz &> /dev/null
	-rm -rf $(distdir) &> /dev/null

.PHONY: all verbose clean analyze check install uninstall dist distcheck
.PHONY: FORCE
