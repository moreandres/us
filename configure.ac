# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([us],[0.0.1],[more.andres@gmail.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/us.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stddef.h])
AC_CHECK_HEADERS([stdint.h])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([sys/socket.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset gettimeofday])

AC_SEARCH_LIBS(pthread_create, pthread, [], AC_MSG_ERROR([missing pthread_create]))
AC_SEARCH_LIBS(MHD_start_daemon, microhttpd, [], AC_MSG_ERROR([missing MHD_start_daemon]))
AC_SEARCH_LIBS(WJRCloseDocument, wjreader, [], AC_MSG_ERROR([missing WJRCloseDocument]))
AC_SEARCH_LIBS(WJEObjectF, wjelement, [], AC_MSG_ERROR([missing WJEObject]))
AC_SEARCH_LIBS(criterion_register_test, criterion, [], AC_MSG_ERROR([missing criterion]))

AC_CONFIG_FILES([Makefile src/Makefile t/Makefile t/ut/Makefile t/st/Makefile t/qa/Makefile])

AC_OUTPUT
