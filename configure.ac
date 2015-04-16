#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for libraries.
LDFLAGS="-L/usr/lib/libmilter $LDFLAGS"
AX_PATH_MILTER([8.11], [],[ AC_MSG_ERROR([required milter library and header not found]) ])
AC_CHECK_LIB([spf2], [SPF_server_new],
	     [
		 AC_SUBST(SPF2_LIBS, [-lspf2])
	     ],
	     [
	         AC_MSG_ERROR([required spf2 library not found])
	     ])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h sys/time.h sys/socket.h netdb.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset gettimeofday])

AC_OUTPUT
