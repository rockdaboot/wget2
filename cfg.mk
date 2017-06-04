# Explicit syntax-check exceptions.
VC_LIST_ALWAYS_EXCLUDE_REGEX = ^data/.*|tests/files/.*|.*.png|^fuzz/.*.in/.*|.*.repro/.*$$

local-checks-to-skip = \
  sc_cast_of_argument_to_free \
  sc_immutable_NEWS \
  sc_makefile_at_at_check \
  sc_prohibit_always_true_header_tests \
  sc_prohibit_atoi_atof \
  sc_prohibit_strcmp

# Explicit syntax-check exceptions.
exclude_file_name_regexp--sc_bindtextdomain = ^(tests|unit-tests|examples|fuzz)/.*.c|^libwget/test_linking.c$$
exclude_file_name_regexp--sc_po_check = ^examples/|tests/.*.c$$
exclude_file_name_regexp--sc_prohibit_magic_number_exit = tests/.*.c$$
exclude_file_name_regexp--sc_trailing_blank = docs/DoxygenLayout.xml|docs/libwget.doxy.in$$
exclude_file_name_regexp--sc_two_space_separator_in_usage = docs/wget2_manual.md$$
exclude_file_name_regexp--sc_require_config_h = examples/.*.c|fuzz/main.c$$
exclude_file_name_regexp--sc_require_config_h_first = examples/.*.c|fuzz/main.c$$
