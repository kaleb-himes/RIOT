#ifdef BOARD_NATIVE
//#   define WOLFSSL_GENERAL_ALIGNMENT 8
#else
#   define WOLFSSL_GENERAL_ALIGNMENT 4
#   ifdef CPU_ARM
#      define TFM_ARM
#   endif
#endif

#define NO_WOLFSSL_MEMORY
#define RSA_LOW_MEM
#define NO_OLD_RNGNAME
#define SMALL_SESSION_CACHE
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_DTLS
#define WOLFSSL_GNRC
#define WOLFSSL_USER_IO

#define SINGLE_THREADED
#define NO_SIG_WRAPPER

#define HAVE_FFDHE_2048
#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_ECC
#define HAVE_CURVE25519
#define CURVED25519_SMALL
#define HAVE_ONE_TIME_AUTH
#define WOLFSSL_DH_CONST
#define WORD64_AVAILABLE

#define HAVE_ED25519
#define HAVE_POLY1305
#define HAVE_SHA512
#define WOLFSSL_SHA512

#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

#define NO_WRITEV
#define NO_DEV_RANDOM
#define NO_FILESYSTEM
#define NO_MAIN_DRIVER
#define NO_MD4
#define NO_RABBIT
#define NO_HC128

#undef WOLFSSL_RIOT_OS
#define WOLFSSL_RIOT_OS

#undef NO_MAIN_DRIVER
#define NO_MAIN_DRIVER

#undef HAVE_ECC
#define HAVE_ECC

#undef TFM_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT

#undef ECC_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

#undef WC_RSA_BLINDING
#define WC_RSA_BLINDING

#undef NO_FILESYSTEM
#define NO_FILESYSTEM

#undef SINGLE_THREADED
#define SINGLE_THREADED

#undef USE_CERT_BUFFER_2048
#define USE_CERT_BUFFERS_2048

#include <random.h>
#define CUSTOM_RAND_GENERATE random_uint32
#define CUSTOM_RAND_TYPE uint32_t

int strncasecmp(const char *s1, const char * s2, unsigned int sz);
