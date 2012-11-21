# -D_FORTIFY_SOURCE=2 -Wmissing-prototypes -Wold-style-definition -Wstack-protector -Wconversion
CC=$(SILENT)gcc
CFLAGS=-g -std=gnu99 -pedantic -fPIC\
 -Wall -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes\
 -Wwrite-strings -Wformat=2 -Wformat -Wformat-security\
 -fstack-protector --param ssp-buffer-size=4\
 -Wno-sign-compare -Wextra -D_FORTIFY_SOURCE=2\
 -Wundef -Wcast-align -O2\
 -D _FILE_OFFSET_BITS=64\
 -D ENABLE_NLS=1

LDFLAGS=-fPIE -pie -Wl,-z,relro,--as-needed

TARGETS=test buffer_printf2_perf stringmap_perf
SOURCES=$(wildcard *.c)
HEADERS=$(wildcard *.h)
#OBJECTS=$(SOURCES:%.c=%.o)
MGET_OBJECTS=$(shell ls ../src/*.o 2>/dev/null|grep -v mget.o)

all:
	@SILENT="@" $(MAKE) --no-print-directory targets

verbose:
	@SILENT="" $(MAKE) --no-print-directory targets

.depend: $(SOURCES) $(HEADERS)
	@$(CC) -MM $(SOURCES) > .depend

objects: $(OBJECTS) .depend
	@echo -n

targets: $(TARGETS) .depend
	@echo -n

analyze:
	clang --analyze $(SOURCES)

check: targets
	valgrind -q --leak-check=full --track-origins=yes --show-reachable=yes ./test

clean:
	@echo Removing objects and binaries...
	-@rm -rf .depend $(OBJECTS) $(TARGETS) *.plist

.c.o:
	@echo Compiling $(@F)
	$(CC) $(CFLAGS) $(CPPLAGS)-c $< -o $@

#.SECONDARY:

# default rule to create .o files from .c files
#%.o: %.c
#	@echo Compiling $(@F)
#	$(CC) -c $< -o $@

# default rule to link executables
%: %.o $(OBJECTS) $(MGET_OBJECTS)
	@echo Linking $(@F) ...
	$(CC) $(LDFLAGS) $^ -o $@ -lgnutls -lpthread -lz

stringmap_perf: stringmap_perf.o $(MGET_OBJECTS)
	@echo Linking $(@F) ...
	$(CC) $(LDFLAGS) $^ -o $@ -lgnutls -lpthread -lz

-include .depend
.PHONY: clean analyze
