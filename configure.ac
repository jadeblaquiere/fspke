AC_INIT([libfspke], [0.1], [https://github.com/jadeblaquiere/fspke/issues])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_PROG_CC
AM_PROG_AR
LT_INIT
AC_ARG_ENABLE([examples],
[  --enable-examples       build examples @<:@default=no@:>@],
[case "${enableval}" in
  yes) examples=true ;;
  no)  examples=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-examples]) ;;
esac],[debug=false])
AM_CONDITIONAL([COND_EXAMPLES], [test "x$examples" = xtrue])
AC_CHECK_LIB(gmp, __gmpz_init)
AC_CHECK_LIB(ecc, mpFp_init)
AC_CHECK_LIB(pbc, element_printf)
AC_CHECK_LIB(tasn1, asn1_create_element)
AM_COND_IF([COND_EXAMPLES],[AC_CHECK_LIB(popt, poptGetContext)])
AM_COND_IF([COND_EXAMPLES],[AC_CHECK_LIB(b64, base64_init_encodestate)])
AM_COND_IF([COND_EXAMPLES],[AC_CHECK_LIB(sodium, randombytes_buf)])
PKG_CHECK_MODULES([CHECK], [check])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_OUTPUT([Makefile src/Makefile tests/Makefile examples/Makefile include/Makefile])
