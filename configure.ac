#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.69])
AC_INIT([CHEEZFS], [0.0.1])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([README.md])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AR
LT_INIT

# Checks for libraries.
PKG_CHECK_MODULES([FUSE], [fuse3])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
