AC_INIT([Intel(R) EPID SDK],[ ])

# save flags
CFLAGS_OLD="$CFLAGS"
CPPFLAGS_OLD="$CPPFLAGS"

#c compiler priority
AC_PROG_CC([gcc icc cc])
#c++ compiler priority
AC_PROG_CXX([g++ icpc c++])
#define ranlib
AC_PROG_RANLIB()
# restore flags
CFLAGS="$CFLAGS_OLD"
CPPFLAGS="$CPPFLAGS_OLD"

AC_ARG_WITH([config],
    AS_HELP_STRING([--with-config=type],
    [Choose config type. Possible options are:
    --with-config=release,
    --with-config=size_optimized_release.
    Default is 'release' if no option is specified.]),
    [],
    [with_config=release]
)

AC_SUBST([CONFIG], ["release"])
AS_IF([test "x$with_config" != "xrelease"], [
  [CONFIG=size_optimized_release]
])

# default install path is current directory
AC_PREFIX_DEFAULT([`pwd`/_install])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

