noinst_PROGRAMS = test_cwhash
TESTS = test_cwhash

test_cwhash_SOURCES = test_cwhash.c
test_cwhash_CFLAGS = -Wall -I ../include $(CFLAGS) $(CHECK_CFLAGS)
test_cwhash_LDADD = -L../src/.libs/ -lfspke -lecc -lgmp $(LDFLAGS) $(CHECK_LIBS)
