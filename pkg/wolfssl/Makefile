PKG_NAME=wolfssl
PKG_URL=https://github.com/danielinux/wolfssl.git
#PKG_URL=https://github.com/wolfssl/wolfssl.git
PKG_VERSION=ff380ff1577151f7c9fc535fd3d9e92f7f04e1d6
PKG_LICENSE=GPLv2

.PHONY: all

all: git-download
	mkdir -p $(BINDIR)/wolfssl/src
	mkdir -p $(BINDIR)/wolfssl/wolfcrypt
	mkdir -p $(BINDIR)/wolfssl/wolfcrypt/src
	mkdir -p $(BINDIR)/wolfssl/wolfcrypt/test
	mkdir -p $(BINDIR)/sock_tls/
	cp Makefile.wolfssl $(PKG_BUILDDIR)/Makefile
	"$(MAKE)" -C $(PKG_BUILDDIR)/

include $(RIOTBASE)/pkg/pkg.mk
