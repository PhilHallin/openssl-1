#ifndef HEADER_MSCRYPTCURL_H
# define HEADER_MSCRYPTCURL_H


# include "mscrypt.h"
# include <curl/curl.h>

#ifdef  __cplusplus
extern "C" {
#endif

CURLcode MSCRYPT_curl_setopt_ssl_client(
    CURL *curl,
    MSCRYPT_VERIFY_CERT_CTX *ctx,   // Optional
    const char *pemFilename,        // Optional, set for client auth
    const char *engineName,         // Optional, set for client auth
    const char *engineKeyId);       // Optional, set for client auth

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_MSCRYPTCURL_H */
