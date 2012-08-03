# -Wstack-protector -Wconversion
CC=$(SILENT)gcc
CFLAGS=-g -std=gnu99 -pedantic -fPIC\
 -Wall -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes\
 -Wwrite-strings -Wformat=2 -Wformat -Wformat-security\
 -fstack-protector --param ssp-buffer-size=4\
 -Wno-sign-compare -Wextra -D_FORTIFY_SOURCE=2\
 -Wundef -Wcast-align -O2\
 -D _FILE_OFFSET_BITS=64\
 -D ENABLE_NLS=1\
 -D LOCALEDIR=\"/usr/share/locale\"

#LN=$(SILENT)gcc -fPIE -pie -Wl,-z,relro,-z,now
LN=$(SILENT)gcc -fPIE -pie -Wl,-z,relro,--as-needed

TARGETS=mget
SOURCES=$(wildcard *.c) css_tokenizer.c
HEADERS=$(wildcard *.h)
OBJECTS=$(SOURCES:%.c=%.o)

all:
	@SILENT="@" $(MAKE) --no-print-directory targets

verbose:
	@SILENT="" $(MAKE) --no-print-directory targets

.depend: $(SOURCES) $(HEADERS)
	@$(CC) -MM $(SOURCES) > .depend

objects: $(OBJECTS) .depend
	@echo -n

targets: css_tokenizer.c .depend $(TARGETS)
	@echo -n

analyze:
	clang --analyze $(SOURCES)

clean:
	@echo Removing objects and binaries...
	-@rm -f .depend $(OBJECTS) $(TARGETS)

css_tokenizer.c: css_tokenizer.lex css_tokenizer.h
	flex -o $@ $<

.c.o:
	@echo Compiling $(@F)
	$(CC) $(CFLAGS) -c $< -o $@

#.SECONDARY:

# default rule to create .o files from .c files
#%.o: %.c
#	@echo Compiling $(@F)
#	$(CC) -c $< -o $@

# default rule to link executables
%: %.o $(OBJECTS)
	@echo Linking $(@F) ...
	$(LN) $^ -o $@ -lpthread -lrt -lgnutls -lz

-include .depend
.PHONY: clean analyze
