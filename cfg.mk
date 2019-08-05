# Explicit syntax-check exceptions.
VC_LIST_ALWAYS_EXCLUDE_REGEX = ^data/.*|tests/(files|gpg|certs)/.*|.*\.png|^fuzz/.*\.(in|repro)/.*$$

# Can someone please check if we can replace the @...@ for MACOSX_LIBS to use
# the $(...) format? Then remove the at_at_check exception

local-checks-to-skip = \
  sc_cast_of_argument_to_free \
  sc_immutable_NEWS \
  sc_makefile_at_at_check \
  sc_prohibit_atoi_atof \
  sc_prohibit_gnu_make_extensions \
  sc_prohibit_strcmp

# Explicit syntax-check exceptions.
exclude_file_name_regexp--sc_bindtextdomain = ^(tests|unit-tests|examples|fuzz)/.*\.c|^libwget/test_linking.*\.c$$
exclude_file_name_regexp--sc_po_check = ^examples/|tests/.*\.c$$
exclude_file_name_regexp--sc_prohibit_magic_number_exit = tests/.*\.c$$
exclude_file_name_regexp--sc_trailing_blank = docs/DoxygenLayout\.xml|docs/libwget\.doxy\.in|contrib/assignment_template\.txt$$
exclude_file_name_regexp--sc_two_space_separator_in_usage = \.gitlab-ci\.yml|docs/wget2_manual\.md$$
exclude_file_name_regexp--sc_require_config_h = examples/.*\.c|fuzz/main\.c$$
exclude_file_name_regexp--sc_require_config_h_first = examples/.*\.c|fuzz/main\.c$$
exclude_file_name_regexp--sc_copyright_check = .*gnulib/.*\.c$$
exclude_file_name_regexp--sc_prohibit_empty_lines_at_EOF = contrib/assignment_template\.txt$$
exclude_file_name_regexp--sc_prohibit_sprintf = benchmarks/benches/convert\.gp$$
exclude_file_name_regexp--sc_prohibit_printf = ^(unit-tests/(test\.c|buffer_printf_perf\.c)|examples/.*\.c|libwget/strlcpy\.c)$$
exclude_file_name_regexp--sc_prohibit_free = ^(cfg\.mk|fuzz/.*\.c|unit-tests/.*\.c)$$
exclude_file_name_regexp--sc_prohibit_alloc = ^(fuzz/.*\.c)$$
exclude_file_name_regexp--sc_gettext_printf = ^(fuzz|tests|unit-tests|examples)/.*\.c|.*\.h|libwget/test_linking.*\.c$$
exclude_file_name_regexp--sc_GPL_version = ^m4/.*\.m4

sc_prohibit_sprintf:
        @prohibit='\<sprintf *\(' \
        halt='do not use sprintf() as it does not check the output buffer size' \
          $(_sc_search_regexp)

sc_prohibit_printf:
	@prohibit='\<(sn|vsn|f|vf|vfn|as|vas)printf *\(' \
	halt='do not use libc printf functions, instead use the wget_ pendants' \
	  $(_sc_search_regexp)

sc_prohibit_free:
	@prohibit='[[:space:];,][[:space:];,]*\<free *\(.*\)[;,]' \
	halt='do not use free(), instead use the wget_free() or the xfree macro' \
	  $(_sc_search_regexp)

sc_prohibit_alloc:
	@prohibit='[[:space:];,][[:space:];,]*\<(m|c|re)alloc *\(.*\)[;,]' \
	halt='do not use libc malloc functions, instead use the wget_* pendants' \
	  $(_sc_search_regexp)

sc_prohibit_gettext_debug:
	@prohibit='\<(wget_|)debug_printf *\( *_ *\(' \
	halt='do not translate debug strings' \
	  $(_sc_search_regexp)

sc_gettext_printf:
	@prohibit='\<(wget_|)(info|error)_printf *\( *[^_]' \
	exclude='(//.*\<(wget_|)(info|error)_printf|\<wget_(info|error)_printf\(const |no translation)' \
	halt='use _() to translate info and error strings' \
	  $(_sc_search_regexp)
