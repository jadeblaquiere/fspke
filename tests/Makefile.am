noinst_PROGRAMS = test_cwhash test_icarthash test_sparsetree
TESTS = test_cwhash test_icarthash test_sparsetree

test_cwhash_SOURCES = test_cwhash.c
test_cwhash_CFLAGS = -Wall -I ../include $(CFLAGS) $(CHECK_CFLAGS)
test_cwhash_LDADD = -L../src/.libs/ -lfspke -lecc -lgmp $(LDFLAGS) $(CHECK_LIBS)

test_icarthash_SOURCES = test_icarthash.c
test_icarthash_CFLAGS = -Wall -I ../include $(CFLAGS) $(CHECK_CFLAGS)
test_icarthash_LDADD = -L../src/.libs/ -lfspke -lecc -lgmp $(LDFLAGS) $(CHECK_LIBS)

test_sparsetree_SOURCES = test_sparsetree.c
test_sparsetree_CFLAGS = -Wall -I ../include $(CFLAGS) $(CHECK_CFLAGS)
test_sparsetree_LDADD = -L../src/.libs/ -lfspke -lecc -lgmp $(LDFLAGS) $(CHECK_LIBS)
