PKG_NAME=wolfssl
PKG_URL=https://github.com/danielinux/wolfssl.git
#PKG_URL=https://github.com/wolfssl/wolfssl.git
PKG_VERSION=ff380ff1577151f7c9fc535fd3d9e92f7f04e1d6
PKG_LICENSE=GPLv2

.PHONY: all

all: git-download
	mkdir -p $(PKG_BUILDDIR)/../../../$(BOARD)/wolfssl/src
	mkdir -p $(PKG_BUILDDIR)/../../../$(BOARD)/wolfssl/wolfcrypt
	mkdir -p $(PKG_BUILDDIR)/../../../$(BOARD)/wolfssl/wolfcrypt/src
	mkdir -p $(PKG_BUILDDIR)/../../../$(BOARD)/wolfssl/wolfcrypt/test
	mkdir -p $(PKG_BUILDDIR)/../../../$(BOARD)/sock_tls/
	cp Makefile.wolfssl $(PKG_BUILDDIR)/Makefile
	"$(MAKE)" -C $(PKG_BUILDDIR)/

include $(RIOTBASE)/pkg/pkg.mk
