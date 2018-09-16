# Option Handling In Wget2

In this document, we try to explain how the command line options are handled
within `Wget2`. Due to the nature of an evolving program, this documentation
may soon become out-of-date. If you notice any inconsistencies, please either
raise an issue or fix them yourself.

## Add a new Command Line Option

All the code related to handling the command line options resides in
[`src/options.c`](https://gitlab.com/gnuwget/wget2/blob/master/src/options.c)
and
[`src/wget_options.h`](https://gitlab.com/gnuwget/wget2/blob/master/src/wget_options.h).

To add a new option, first open `src/wget_options.h` and add a new variable in
`struct config` which will be used to hold the value passed the user.

The command line options are defined in `src/options.c` in `struct options`. To
add a new option, navigate to the struct definition and add a new entry to the
struct, **in lexicographic order of long-name**, consisting of:

  1. Long Name: This is the exact long form of the option as will be used by
	 the user.
  2. Config Option: This is a pointer to the variable which holds the value
	 passed by the user. Add a pointer to the variable created above in `struct
	 config` here.
  3. Parsing Function: Mention the name of the [parsing
	 function](https://gitlab.com/gnuwget/wget2/wikis/Documentation/OptionHandling#parsing-functions) to use for this option.
  4. Argument Number: The number of arguments that this option may accept.
	 Enter "-1" here if the option does not accept any arguments (Boolean
	 options).
  5. Short Name: This the short form of the command line option, which will be
	 accessed using a single hyphen (-). Only the more commonly used options
	 should be given a short name, since the number of available options are
	 limited. If the option does not need a short name, pass `0` in this field.
  6. Section: Name the [Section](https://gitlab.com/gnuwget/wget2/wikis/Documentation/OptionHandling#sections) under which this option should be
	 listed in the help output. This is purely for aesthetic purposes and has
	 no bearing on the internal workings of the codebase.
  7. Help String: This is the help string which is displayed during `--help`.
	 Explain the option here in one or two lines. Remember to break lines after
	 50 characters. Also, mention any default values here.

If the option needs a default value which is different from the default value
of its data type under the C standard, then set the default value during the
creation of the `struct config` in `src/options.c`.

If the option stores something on the heap, then you must also free the
relevant memory to prevent any memory leaks. For this, free the relevant memory
from the `deinit()` function.

Sometimes, an option requires sanity checking. This may be because it can
accept only a limited set of values or is mutually exclusive with another
option. Such checks should be performed early in the program to prevent
performing unnecessary computations. All such checks are currently done in the
`init()` function in `src/options.c` after the logging has been initialized.

### Parsing Functions

In order to aid in parsing the command line input, various parsing functions
are provided. Each option must mention the parser that is used to handle it.
All parsing functions have the following signature:

```
	static int parse_function_name (option_t opt, const char *val, const char invert);
```

Each parser returns the number of arguments to the option that it processed.
The `invert` parameter of the function is set to `1` if the user passed the
command line option with `no-` prefixed to it. This way, *all* options have a
negation supported by default

#### List of Parsing Functions

As of this writing, the following parsing functions are available:

   - parse\_bool
   - parse\_cert\_type
   - parse\_command\_line
   - parse\_compression
   - parse\_execute
   - parse\_filename
   - parse\_filenames
   - parse\_header
   - parse\_https\_enforce
   - parse\_integer
   - parse\_local\_db
   - parse\_mirror
   - parse\_n\_option
   - parse\_numbytes
   - parse\_plugin
   - parse\_plugin\_dirs
   - parse\_plugin\_local
   - parse\_plugin\_option
   - parse\_prefer\_family
   - parse\_progress\_type
   - parse\_proxy
   - parse\_regex\_type
   - parse\_report\_speed\_type
   - parse\_restrict\_names
   - parse\_stats\_all
   - parse\_string
   - parse\_stringlist
   - parse\_stringlist\_expand
   - parse\_stringset
   - parse\_taglist
   - parse\_timeout
   - parse\_uint16

### Sections

Since `wget2` contains a lot of options, they are organized within a set number
of sections. Each command should fall into one of the following sections:

  * SECTION\_STARTUP
  * SECTION\_DOWNLOAD
  * SECTION\_HTTP
  * SECTION\_SSL
  * SECTION\_DIRECTORY
  * SECTION\_GPG
  * SECTION\_PLUGIN
