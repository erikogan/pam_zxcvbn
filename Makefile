DESTDIR=/
LIBDIR=/usr/lib64
PAM_LIB_DIR=$(LIBDIR)/security
# DEBUG_OR_OPTIMIZE=-O2
DEBUG_OR_OPTIMIZE=-g

CC=gcc
LDFLAGS=-lzxcvbn -lm -lpam
CFLAGS=$(DEBUG_OR_OPTIMIZE) -fPIC -Wall

pam_zxcvbn.so: pam_zxcvbn.o
	gcc --shared -o $@ $^ $(LDFLAGS) -Wl,-rpath,$(PAM_LIB_DIR)

test: test.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS)

install:
	mkdir -p $(DESTDIR)/$(PAM_LIB_DIR)
	install pam_zxcvbn.so $(DESTDIR)/$(PAM_LIB_DIR)

clean:
	rm -f test *.o *.so
