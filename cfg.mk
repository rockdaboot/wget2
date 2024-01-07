# Copyright (C) 2015-2024 Free Software Foundation, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Explicit syntax-check exceptions.
VC_LIST_ALWAYS_EXCLUDE_REGEX = ^data/.*|tests/(files|gpg|certs)/.*|.*\.png|^fuzz/.*\.(in|repro)/.*$$

# Syntax Check Rules that we want to skip
#  * sc_immutable_NEWS: I can't make this test ever pass. If someone fixes it,
#  happy to remove it from here.
#  * sc_makefile_at_at_check: We seem to use it predominantly for setting
#  INTL_MACOSX_LIBS. Without access to a mac, there's no way to verify if it
#  supports usage of the $(VAR) notation
#  * sc_prohibit_atoi_atof: We use a lot of sscaf() to parse strings
#  * sc_prohibit_gnu_make_extensions: We use GNU make.
#  * sc_prohibit_strcmp: I don't like blind adherence to such rules. We try to
#  use strcmp correctly everywhere
local-checks-to-skip =            \
  sc_immutable_NEWS               \
  sc_makefile_at_at_check         \
  sc_prohibit_atoi_atof           \
  sc_prohibit_gnu_make_extensions \
  sc_prohibit_strcmp              \
  sc_indent                       \
  sc_error_message_uppercase      \
  sc_readme_link_install          \
  sc_readme_link_copying          \
  sc_unportable_grep_q

update-copyright-env = UPDATE_COPYRIGHT_FORCE=1 UPDATE_COPYRIGHT_USE_INTERVALS=1

# Explicit syntax-check exceptions.

## The file is indeed licensed under LGPLv2.1+. But the script doesn't parse that correctly
exclude_file_name_regexp--sc_GPL_version = ^m4/ax_code_coverage.m4$
## These are dev specific files and don't need to be localised
exclude_file_name_regexp--sc_bindtextdomain = ^(tests|unit-tests|examples|fuzz)/.*\.c|^libwget/test_linking.*\.c$$
## This is a bug in gnulib that I've already reported
exclude_file_name_regexp--sc_prohibit_magic_number_exit = ^(tests/test-plugin\.c|unit-tests/test-dl\.c)$$
## Not all c files require the config.h file
exclude_file_name_regexp--sc_require_config_h = examples/.*\.c|fuzz/main\.c$$
exclude_file_name_regexp--sc_require_config_h_first = examples/.*\.c|fuzz/main\.c$$
# do not remove, takes care for dependency subdirs (e.g. when using contrib/mingw script)
exclude_file_name_regexp--sc_copyright_check = .*gnulib/.*\.c$$
# do not complain about Dockerfiles
exclude_file_name_regexp--sc_two_space_separator_in_usage = contrib/Dockerfile.*

# The assignment_template is copies as-is into an email. Don't add any headers
# there. The m4/* files are copied from autoconf-archive and don't follow the
# same copyright convention
exclude_file_name_regexp--update-copyright = ^(contrib/assignment_template\.txt|m4/(ax_ac_append_to_file|ax_ac_print_to_file|ax_add_am_macro_static|ax_am_macros_static|ax_check_gnu_make|ax_code_coverage|ax_file_escapes).m4|contrib/make-coverage-badge)$$

# We don't care for trailing spaces in announcements.
exclude_file_name_regexp--sc_trailing_blank = docs/announce.*\.txt$$

update-version-year:
	$(AM_V_at)$(SED) -i "s/(C) 2015-.... Free Software Foundation/(C) 2015-`date +%Y` Free Software Foundation/g" src/options.c

update-copyright: update-version-year

# New syntax-check rules
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


exclude_file_name_regexp--sc_gettext_printf = ^(tests|unit-tests|examples|fuzz)/.*\.c|^libwget/test_linking.*\.c$$
exclude_file_name_regexp--sc_prohibit_alloc = ^(fuzz/.*\.c)$$
exclude_file_name_regexp--sc_prohibit_free = ^(cfg.mk|fuzz/.*\.c|unit-tests/.*\.c)$$
exclude_file_name_regexp--sc_prohibit_printf = ^(unit-tests/.*\.c|examples/.*\.c|libwget/strlcpy\.c)$$
