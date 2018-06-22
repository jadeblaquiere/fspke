if COND_SAFECLEAN
  MAYBE_SAFECLEAN = -DSAFE_CLEAN
endif

noinst_PROGRAMS = chk_gen chk_pub chk_der chk_enc chk_dec
CLEANFILES=chk_example_asn1_tab.c
chk_example_asn1_tab.c: chk_example.asn
	asn1Parser chk_example.asn

chk_gen_SOURCES = chk_gen.c b64file.c
chk_gen_CFLAGS = -Wall $(MAYBE_SAFECLEAN) -I ../include -I $(prefix)/include/pbc $(CFLAGS)
chk_gen_LDADD = -L../src/.libs/ -lfspke -lecc -lgmp -lpbc -ltasn1 -lpopt -lb64 $(LDFLAGS)

chk_pub_SOURCES = chk_pub.c b64file.c
chk_pub_CFLAGS = -Wall $(MAYBE_SAFECLEAN) -I ../include -I $(prefix)/include/pbc $(CFLAGS)
chk_pub_LDADD = -L../src/.libs/ -lfspke -lecc -lgmp -lpbc -ltasn1 -lpopt -lb64 $(LDFLAGS)

chk_der_SOURCES = chk_der.c b64file.c
chk_der_CFLAGS = -Wall $(MAYBE_SAFECLEAN) -I ../include -I $(prefix)/include/pbc $(CFLAGS)
chk_der_LDADD = -L../src/.libs/ -lfspke -lecc -lgmp -lpbc -ltasn1 -lpopt -lb64 $(LDFLAGS)

chk_enc_SOURCES = chk_enc.c b64file.c chk_example_asn1_tab.c
chk_enc_CFLAGS = -Wall $(MAYBE_SAFECLEAN) -I ../include -I $(prefix)/include/pbc $(CFLAGS)
chk_enc_LDADD = -L../src/.libs/ -lfspke -lecc -lgmp -lpbc -ltasn1 -lpopt -lb64 -lsodium $(LDFLAGS)

chk_dec_SOURCES = chk_dec.c b64file.c chk_example_asn1_tab.c
chk_dec_CFLAGS = -Wall $(MAYBE_SAFECLEAN) -I ../include -I $(prefix)/include/pbc $(CFLAGS)
chk_dec_LDADD = -L../src/.libs/ -lfspke -lecc -lgmp -lpbc -ltasn1 -lpopt -lb64 -lsodium $(LDFLAGS)
