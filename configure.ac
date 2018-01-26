AC_INIT([libfspke], [0.1], [https://github.com/jadeblaquiere/fspke/issues])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_PROG_CC
AM_PROG_AR
LT_INIT
AC_CHECK_LIB(gmp, mpz_init)
AC_CHECK_LIB(ecc, mpFp_init)
AC_CHECK_LIB(pbc, element_init)
AC_CHECK_LIB(tasn1, asn1_create_element)
AC_CHECK_LIB(popt, poptGetContext)
AC_CHECK_LIB(b64, base64_init_encodestate)
PKG_CHECK_MODULES([CHECK], [check])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_OUTPUT([Makefile src/Makefile tests/Makefile examples/Makefile include/Makefile])
