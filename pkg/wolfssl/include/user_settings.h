/* HACK include user settings from the application until it is handled with
 * modules */
#include "application_user_settings.h"

#undef HAVE_ECC
#ifdef MODULE_WOLFCRYPT_ECC
  #define HAVE_ECC
#endif
