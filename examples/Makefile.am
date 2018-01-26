noinst_PROGRAMS = chk_gen chk_pub

chk_gen_SOURCES = chk_gen.c b64file.c
chk_gen_CFLAGS = -Wall -I ../include -I /usr/include/pbc $(CFLAGS)
chk_gen_LDADD = -L../src/.libs/ -lfspke -lecc -lgmp -lpbc -ltasn1 -lpopt -lb64 $(LDFLAGS)

chk_pub_SOURCES = chk_pub.c b64file.c
chk_pub_CFLAGS = -Wall -I ../include -I /usr/include/pbc $(CFLAGS)
chk_pub_LDADD = -L../src/.libs/ -lfspke -lecc -lgmp -lpbc -ltasn1 -lpopt -lb64 $(LDFLAGS)
