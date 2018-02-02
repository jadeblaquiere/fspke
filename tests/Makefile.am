noinst_PROGRAMS = test_chkpke test_cwhash test_icarthash test_sparsetree
TESTS = test_cwhash test_icarthash test_sparsetree test_chkpke

test_chkpke_SOURCES = test_chkpke.c
test_chkpke_CFLAGS = -Wall -I ../include -I $(prefix)/include/pbc $(CFLAGS) $(CHECK_CFLAGS)
test_chkpke_LDADD = -L../src/.libs/ -lfspke -lecc -lgmp -lpbc -ltasn1 $(LDFLAGS) $(CHECK_LIBS)

test_cwhash_SOURCES = test_cwhash.c
test_cwhash_CFLAGS = -Wall -I ../include $(CFLAGS) $(CHECK_CFLAGS)
test_cwhash_LDADD = -L../src/.libs/ -lfspke -lecc -lgmp -lpbc -ltasn1 $(LDFLAGS) $(CHECK_LIBS)

test_icarthash_SOURCES = test_icarthash.c
test_icarthash_CFLAGS = -Wall -I ../include $(CFLAGS) $(CHECK_CFLAGS)
test_icarthash_LDADD = -L../src/.libs/ -lfspke -lecc -lgmp -lpbc -ltasn1 $(LDFLAGS) $(CHECK_LIBS)

test_sparsetree_SOURCES = test_sparsetree.c
test_sparsetree_CFLAGS = -Wall -I ../include $(CFLAGS) $(CHECK_CFLAGS)
test_sparsetree_LDADD = -L../src/.libs/ -lfspke -lecc -lgmp -lpbc -ltasn1 $(LDFLAGS) $(CHECK_LIBS)
