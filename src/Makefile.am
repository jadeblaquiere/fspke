BUILT_SOURCES=fspke_asn1_tab.c
lib_LTLIBRARIES=libfspke.la
libfspke_la_SOURCES = chkpke.c cwhash.c icarthash.c sparsetree.c fspke_asn1_tab.c
libfspke_la_CFLAGS = -Wall -I ../include -I /usr/include/pbc
libfspke_la_LDFLAGS = -version-info 0:0:0
CLEANFILES=fspke_asn1_tab.c
fspke_asn1_tab.c: fspke.asn
	asn1Parser fspke.asn