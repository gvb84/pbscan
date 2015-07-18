NETMAP_DIR=netmap
UINET_DIST_DIR=libuinet
UINET_DIR=libuinet/lib/libuinet
UINET_ARCHIVE=$(UINET_DIR)/libuinet.a
EV_DIR=libuinet/lib/libev
EV_ARCHIVE=$(EV_DIR)/.libs/libev.a
CFLAGS=-I/usr/include -I $(UINET_DIR)/api_include -Wall -Werror $(DEBUG_FLAGS)
LFLAGS=-lpcap -lpthread -lcrypto -lm -lrt
OBJECTS=utils.o range.o sha1.o hmac.o route.o time.o scan.o
DISTFILES=CHANGELOG DEPENDENCIES README LICENSE VERSION TODO Makefile \
	download.sh libuinet.patch
VERSION=$(shell head -n1 VERSION)
TARDIR=pbscan-$(VERSION)
BIN=pbscan

all: $(EV_ARCHIVE) $(UINET_ARCHIVE) $(BIN)

debug: CFLAGS += -DDEBUG -g -ggdb
debug: $(EV_ARCHIVE) $(UINET_ARCHIVE) $(BIN)

libuinet:
	./download.sh
	patch -d libuinet -p1 < libuinet.patch

$(UINET_ARCHIVE): libuinet $(UINET_DIR)/uinet_api.c
	$(MAKE) -C $(UINET_DIR) NETMAP_INCLUDES=../../../netmap/sys

$(EV_ARCHIVE): libuinet $(EV_DIR)/config.status
	$(MAKE) -C $(EV_DIR)

$(EV_DIR)/config.status:
	cd $(EV_DIR) && ./configure --with-uinet=../../../$(UINET_DIR)/api_include

$(BIN): $(OBJECTS)
	$(CC) $(OBJECTS) $(UINET_ARCHIVE) $(EV_ARCHIVE) $(LFLAGS) -o $@
	strip $@

version.h: VERSION
	echo "const char * polarbearscan_version = \"$(VERSION)\";" > version.h

scan.o: version.h scan.c
	$(CC) scan.c -c $(CFLAGS) -o $@

.c.o:
	$(CC) $< -c $(CFLAGS) -o $@

clean:
	$(RM) -r $(OBJECTS) $(BIN)
	$(MAKE) -C $(UINET_DIR) clean

distclean: clean
	$(RM) -r $(UINET_DIST_DIR) $(NETMAP_DIR) tags

tarball:
	mkdir /tmp/$(TARDIR)
	cp *.c *.h $(DISTFILES) /tmp/$(TARDIR)
	cd /tmp && tar zcf $(TARDIR).tar.gz $(TARDIR) && cd - && mv /tmp/$(TARDIR).tar.gz .
	rm -rf /tmp/$(TARDIR)
