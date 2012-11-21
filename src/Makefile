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

install:
	install -d $(DESTDIR)$(prefix)/bin
	install -m 0755 mget $(DESTDIR)$(prefix)/bin

uninstall:
	-rm -f $(DESTDIR)$(prefix)/bin/mget

css_tokenizer.c: css_tokenizer.lex css_tokenizer.h
	flex -o $@ $<

.c.o:
	@echo Compiling $(@F)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

#.SECONDARY:

# default rule to create .o files from .c files
#%.o: %.c
#	@echo Compiling $(@F)
#	$(CC) -c $< -o $@

# default rule to link executables
%: %.o $(OBJECTS)
	@echo Linking $(@F) ...
	$(CC) $(LDFLAGS) $^ -o $@ -lpthread -lrt -lgnutls -lz

-include .depend
.PHONY: all verbose clean analyze install uninstall
