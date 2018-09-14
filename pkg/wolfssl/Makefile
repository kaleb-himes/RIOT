PKG_NAME=wolfssl
PKG_URL=https://github.com/danielinux/wolfssl.git
#PKG_URL=https://github.com/wolfssl/wolfssl.git
PKG_VERSION=859475e30f95a8b12132341da7bb4a2a25869656
PKG_LICENSE=GPLv2

.PHONY: all

all: git-download
	mkdir -p $(BINDIR)/wolfssl/src
	mkdir -p $(BINDIR)/wolfssl/wolfcrypt/src
	mkdir -p $(BINDIR)/wolfssl/wolfcrypt/test
	mkdir -p $(BINDIR)/sock_tls/
	cp Makefile.wolfssl $(PKG_BUILDDIR)/Makefile
	"$(MAKE)" -C $(PKG_BUILDDIR)/

include $(RIOTBASE)/pkg/pkg.mk
