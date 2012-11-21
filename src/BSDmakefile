# -D_FORTIFY_SOURCE=2 -Wmissing-prototypes -Wold-style-definition -Wstack-protector -Wconversion
CC=$(SILENT)gcc
CFLAGS=-g -std=c99 -pedantic -fPIC\
 -Wall -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes\
 -Wwrite-strings -Wformat=2 -Wformat -Wformat-security\
 -fstack-protector --param ssp-buffer-size=4\
 -Wno-sign-compare -Wextra -D_FORTIFY_SOURCE=2\
 -Wundef -Wcast-align -ftrampolines\
 -I /usr/local/include\
 -D _FILE_OFFSET_BITS=64\
 -D ENABLE_NLS=1\
 -D LOCALEDIR=\"/usr/share/locale\"\
 -D GLOBAL_CONFIG_FILE=\"/etc/mgetrc\"

LN=$(SILENT)gcc -fPIE -pie -Wl,-z,relro,-z,now -L/usr/local/lib

TARGETS=mget
SOURCES!=ls *.c
HEADERS!=ls *.h
OBJECTS!=ls *.c|cut -d'.' -f1|awk '{print $$1".o"}'

all:
	@SILENT="@" $(MAKE) targets

verbose:
	@SILENT="" $(MAKE) targets

.depend: $(SOURCES) $(HEADERS)
	@$(CC) -MM $(SOURCES) > .depend

objects: .depend $(OBJECTS)
	@echo -n

targets: css_tokenizer.c .depend $(TARGETS)
	@echo -n

mget: mget.o $(OBJECTS)
	@echo Linking $(@F) ...
	echo $(OBJECTS)
	$(LN) $> -o $@ -lpthread -lgnutls -lz

css_tokenizer.c: css_tokenizer.lex css_tokenizer.h
	flex -o $@ $<

clean:
	@echo Removing objects and binaries...
	-@rm -f .depend $(OBJECTS) $(TARGETS)

# default rule to create .o files from .c files
.c.o:
	@echo Compiling $(@F)
	$(CC) $(CFLAGS) -c $< -o $@

.if exists(.depend)
.include ".depend"
.endif
.PHONY: clean
