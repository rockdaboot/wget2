#ifndef WGETTEST_PLUGIN_H
#define WGETTEST_PLUGIN_H

#define OBJECT_DIR BUILDDIR"/.libs"

#if defined _WIN32
#define LOCAL_NAME(x) OBJECT_DIR "/lib" x ".dll"
#elif defined __CYGWIN__
#define LOCAL_NAME(x) OBJECT_DIR "/cyg" x ".dll"
#else
#define LOCAL_NAME(x) OBJECT_DIR "/lib" x ".so"
#endif

#ifdef _WIN32
#define setenv_rpl(name, value, ignored) _putenv(name "=" value)
#define unsetenv_rpl(name) _putenv(name "=")
#else
#define setenv_rpl setenv
#define unsetenv_rpl unsetenv
#endif


#endif // WGETTEST_PLUGIN_H
