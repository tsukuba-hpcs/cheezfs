sbin_PROGRAMS = cheezfs

cheezfs_SOURCES = cheezfs.c

AM_CPPFLAGS = -g -Wall -pthread @FUSE_CFLAGS@ @JANSSON_CFLAGS@
AM_LDFLAGS = -pthread
LDADD = @FUSE_LIBS@ @JANSSON_LIBS@
