#ifndef HEADER_MSCRYPTP_H
# define HEADER_MSCRYPTP_H

# include "mscrypt.h"
# include <openssl/bio.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define MSCRYPTP_MAX_FILENAME_HASH_LENGTH      16
#define MSCRYPTP_MAX_FILENAME_HEX_HASH_LENGTH  (MSCRYPTP_MAX_FILENAME_HASH_LENGTH * 2 + 1)

#define MSCRYPTP_VERSION_1          1

#define MSCRYPTP_IN_PROC_EXECUTE_FLAG           0x1
#define MSCRYPTP_TRACE_LOG_TEST_EXECUTE_FLAG    0x2
#define MSCRYPTP_TRACE_LOG_VERBOSE_EXECUTE_FLAG 0x4
#define MSCRYPTP_TEST_PFX_SECRET_EXECUTE_FLAG   0x8
void MSCRYPTP_set_execute_flags(
    int flags);

// Call the following to redirect the trace log output
// from stdout to the specified file.
void MSCRYPTP_set_trace_log_filename(
    const char *filename);



typedef struct MSCRYPT_GDBUS_shared_mem_st MSCRYPT_GDBUS_SHARED_MEM;
struct MSCRYPT_shared_mem_st {
    uuid_t                      correlationId;
    int                         memLength;
    unsigned char               *memBytes;
    MSCRYPT_GDBUS_SHARED_MEM    *gdbus;
};

typedef struct MSCRYPT_pfx_ctx_st MSCRYPT_PFX_CTX;
typedef struct MSCRYPT_GBUS_pfx_ctx_st MSCRYPT_GDBUS_PFX_CTX;
struct MSCRYPT_pfx_ctx_st {
    uuid_t                      correlationId;
    void                        *pkey;
    MSCRYPT_GDBUS_PFX_CTX       *gdbus;
};

#ifndef MSCRYPT_ROOT_DIR
#ifdef MSCRYPT_TEST_WINDOWS
#define MSCRYPT_ROOT_DIR ""
#else
#define MSCRYPT_ROOT_DIR "/var/opt/msft/mscrypt"
#endif
#endif

#define MSCRYPT_CERTS_DIR MSCRYPT_ROOT_DIR "/certs"

#ifndef MSCRYPT_INSTALL_IMAGE_DIR
#ifdef MSCRYPT_TEST_WINDOWS
#define MSCRYPT_INSTALL_IMAGE_DIR ""
#else
#define MSCRYPT_INSTALL_IMAGE_DIR "/opt/msft/mscrypt"
#endif
#endif


void MSCRYPTP_set_default_dir(
    const char *defaultCertArea,
    const char *defaultCertDir);

const char *MSCRYPTP_get_default_cert_area();
const char *MSCRYPTP_get_default_cert_dir();
const char *MSCRYPTP_get_install_image_dir();

// Includes NULL terminator character
#define MSCRYPTP_BASE64_ENCODE_LENGTH(inLength) ((((inLength + 3 - 1) / 3) * 4) + 1)

// Returns BIO_s_mem().
// Ensures a NULL terminator is always appended to the read file contents.
BIO *MSCRYPTP_read_file_string(
    const uuid_t correlationId,
    const char *fileName,
    int disableTraceLog,
    char **str);

// Returns number of decode bytes. For a decode error returhs -1.
int MSCRYPTP_base64_decode(
    const uuid_t correlationId,
    const char *str,
    unsigned char **bytes);     // MSCRYPT_free()

// Converts binary bytes to NULL terminated ascii hex characters.
// Returned hex needs (len * 2 + 1) characters
void MSCRYPTP_bytes_to_hex(
    int len,
    const unsigned char *pb,
    char *hex);

int MSCRYPTP_rename_file(
    const uuid_t correlationId,
    const char *title,
    const char *oldFilename,
    const char *newFilename);

int MSCRYPTP_load_pfx_certs(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    X509 **cert,
    STACK_OF(X509) **ca);       // Optional

int MSCRYPTP_pem_from_certs(
    const uuid_t correlationId,
    X509 *cert,                     // Optional
    STACK_OF(X509) *ca,             // Optional
    int *pemCertLength,             // Excludes NULL terminator
    char **pemCert);                // MSCRYPT_free()                   

void MSCRYPTP_get_verify_cert_ctx_correlationId(
    MSCRYPT_VERIFY_CERT_CTX *ctx,
    uuid_t correlationId);

//
// Wrapper for openSSL!X509_verify_cert().
//
// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to build chain
int MSCRYPTP_X509_verify_cert(
    MSCRYPT_VERIFY_CERT_CTX *ctx,
    X509_STORE_CTX *storeCtx,
    int mscryptFlags,
    int *verifyChainError);

typedef struct MSCRYPTP_ctls_ctx_st MSCRYPTP_CTLS_CTX;

MSCRYPTP_CTLS_CTX *MSCRYPTP_get_disallowed_ctls_ctx(
    const uuid_t correlationId);

void MSCRYPTP_release_ctls_ctx(
    MSCRYPTP_CTLS_CTX *ctx);

int MSCRYPTP_is_cert_hash_in_disallowed_ctls_ctx(
    const uuid_t correlationId,
    MSCRYPTP_CTLS_CTX *ctx,
    unsigned char *md,
    int mdLen);

//
// MSCRYPTP_trace_log_* functions
//  Implementation: mscryptsupport.c
// 

extern int MSCRYPTP_traceLogTest;
extern int MSCRYPTP_traceLogVerbose;

#define MSCRYPTP_TRACELOG_PARA_LENGTH       256
#define MSCRYPTP_TRACELOG_ERROR_LENGTH      256

#define MSCRYPTP_TRACELOG_VERBOSE_FLAG      0x1
#define MSCRYPTP_TRACELOG_WARNING_FLAG      0x2

#define MSCRYPTP_ENGINE_TITLE               "MsCryptEngine"
#define MSCRYPTP_SUPPORT_TITLE              "MsCryptSupport"
#define MSCRYPTP_MEMORY_ALLOC_TITLE         "MsCryptMemoryAlloc"
#define MSCRYPTP_IMPORT_PFX_TITLE           "MsCryptImportPfx"
#define MSCRYPTP_OPEN_PFX_TITLE             "MsCryptOpenPfx"
#define MSCRYPTP_CLOSE_PFX_TITLE            "MsCryptClosePfx"
#define MSCRYPTP_HELPER_PFX_TITLE           "MsCryptHelperPfx"
#define MSCRYPTP_PFX_SECRET_TITLE           "MsCryptPfxSecret"
#define MSCRYPTP_IMPORT_TRUSTED_TITLE       "MsCryptImportTrusted"
#define MSCRYPTP_REMOVE_TRUSTED_TITLE       "MsCryptRemoveTrusted"
#define MSCRYPTP_ENUM_TRUSTED_TITLE         "MsCryptEnumTrusted"
#define MSCRYPTP_IS_TRUSTED_TITLE           "MsCryptIsTrusted"
#define MSCRYPTP_IMPORT_DISALLOWED_TITLE    "MsCryptImportDisallowed"
#define MSCRYPTP_REMOVE_DISALLOWED_TITLE    "MsCryptRemoveDisallowed"
#define MSCRYPTP_ENUM_DISALLOWED_TITLE      "MsCryptEnumDisallowed"
#define MSCRYPTP_IS_DISALLOWED_TITLE        "MsCryptIsDisallowed"
#define MSCRYPTP_VERIFY_CERT_TITLE          "MsCryptVerifyCert"
#define MSCRYPTP_HELPER_CERT_TITLE          "MsCryptHelperCert"
#define MSCRYPTP_CREATE_SELF_SIGN_TITLE     "MsCryptCreateSelfSign"
#define MSCRYPTP_RSA_ENCRYPT_TITLE          "MsCryptRsaEncrypt"
#define MSCRYPTP_RSA_DECRYPT_TITLE          "MsCryptRsaDecrypt"
#define MSCRYPTP_ECC_SIGN_TITLE             "MsCryptEccSign"
#define MSCRYPTP_CURL_TITLE                 "MsCryptCurl"
#define MSCRYPTP_TEST_TITLE                 "MsCryptTest"
#define MSCRYPTP_SERVICE_TITLE              "MsCryptService"
#define MSCRYPTP_GDBUS_CLIENT_TITLE         "MsCryptGdbusClient"
#define MSCRYPTP_ERROR_STACK_TITLE          "MsCryptErrorStack"
#define MSCRYPTP_PARSE_CTL_TITLE            "MsCryptParseCtl"
#define MSCRYPTP_IMPORT_DISALLOWED_CTL_TITLE "MsCryptImportDisallowedCtl"
#define MSCRYPTP_REMOVE_DISALLOWED_CTL_TITLE "MsCryptRemoveDisallowedCtl"
#define MSCRYPTP_ENUM_DISALLOWED_CTL_TITLE  "MsCryptEnumDisallowedCtl"

const char *MSCRYPTP_get_cert_ctrl_title(
    int ctrl,
    int location);
const char *MSCRYPTP_get_ctl_ctrl_title(
    int ctrl,
    int location);

void _MSCRYPTP_trace_log_output(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *error,
    const char *paraFormat,
    va_list paraArgs);

void _MSCRYPTP_trace_log_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *format, ...);
#define MSCRYPTP_trace_log_para(correlationId, flags, title, loc, ...) \
    _MSCRYPTP_trace_log_para(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, __VA_ARGS__)

void _MSCRYPTP_trace_log(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc);
#define MSCRYPTP_trace_log(correlationId, flags, title, loc) \
    _MSCRYPTP_trace_log(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc)

void _MSCRYPTP_trace_log_error_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *errStr,
    const char *format, ...);
#define MSCRYPTP_trace_log_error_para(correlationId, flags, title, loc, errStr,  ...) \
    _MSCRYPTP_trace_log_error_para(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, errStr, __VA_ARGS__)

void _MSCRYPTP_trace_log_error(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *errStr);
#define MSCRYPTP_trace_log_error(correlationId, flags, title, loc, errStr) \
    _MSCRYPTP_trace_log_error(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, errStr)

void _MSCRYPTP_trace_log_openssl_error_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *format, ...);
#define MSCRYPTP_trace_log_openssl_error_para(correlationId, flags, title, loc, ...) \
    _MSCRYPTP_trace_log_openssl_error_para(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, __VA_ARGS__)

void _MSCRYPTP_trace_log_openssl_error(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc);
#define MSCRYPTP_trace_log_openssl_error(correlationId, flags, title, loc) \
    _MSCRYPTP_trace_log_openssl_error(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc)


void _MSCRYPTP_trace_log_openssl_verify_cert_error_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    int err,
    const char *format, ...);
#define MSCRYPTP_trace_log_openssl_verify_cert_error_para(correlationId, flags, title, loc, err, ...) \
    _MSCRYPTP_trace_log_openssl_verify_cert_error_para(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, err, __VA_ARGS__)

void _MSCRYPTP_trace_log_openssl_verify_cert_error(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    int err);
#define MSCRYPTP_trace_log_openssl_verify_cert_error(correlationId, flags, title, loc, err) \
    _MSCRYPTP_trace_log_openssl_verify_cert_error(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, err)

void _MSCRYPTP_trace_log_errno_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    int err,
    const char *format, ...);
#define MSCRYPTP_trace_log_errno_para(correlationId, flags, title, loc, err, ...) \
    _MSCRYPTP_trace_log_errno_para(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, err, __VA_ARGS__)

void _MSCRYPTP_trace_log_errno(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    int err);
#define MSCRYPTP_trace_log_errno(correlationId, flags, title, loc, err) \
    _MSCRYPTP_trace_log_errno(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, err)



//
// MSCRYPT_CLIENT_* MSCRYPT_SERVER_* functions
//  Client Implementation: mscryptclient.c
//  Server Implementation: mscryptcert.c, mscryptpfx.c
// 

extern int MSCRYPTP_inProc;

#define MSCRYPT_CERT_LOCATION_ROOT          1 
#define MSCRYPT_CERT_LOCATION_DISALLOWED    2 

#define MSCRYPT_CERT_CTRL_IMPORT            1
#define MSCRYPT_CERT_CTRL_REMOVE            2
#define MSCRYPT_CERT_CTRL_FIND              3
#define MSCRYPT_CERT_CTRL_ENUM              4

int MSCRYPT_CLIENT_cert_ctrl(
    const uuid_t correlationId,
    MSCRYPT_SHARED_MEM *sharedMem,
    int ctrl,
    int location,
    int format,
    int length,
    const unsigned char *bytes);

int MSCRYPT_SERVER_cert_ctrl(
    const uuid_t correlationId,
    int ctrl,
    int location,
    int format,
    int length,
    const unsigned char *bytes);

int MSCRYPT_SERVER_ctl_ctrl(
    const uuid_t correlationId,
    int ctrl,
    int location,
    int length,
    const unsigned char *bytes);

int MSCRYPTP_install_image_certs(
    const uuid_t correlationId);

int MSCRYPT_CLIENT_import_pfx(
    const uuid_t correlationId,
    int mscryptFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inPassword,             // Optional
    int *outVerifyChainError,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // MSCRYPT_free()
    char **outPfxSalt);                 // MSCRYPT_free()

int MSCRYPT_SERVER_import_pfx(
    const uuid_t correlationId,
    int mscryptFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inPassword,             // Optional
    int *outVerifyChainError,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // MSCRYPT_free()
    char **outPfxSalt);                 // MSCRYPT_free()

extern int MSCRYPTP_useTestPfxSecret;

int MSCRYPTP_create_pfx_secret(
    const uuid_t correlationId);

int MSCRYPT_CLIENT_pfx_open(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    const char *salt,
    MSCRYPT_PFX_CTX **keyCtx);

int MSCRYPT_SERVER_pfx_open(
    const uuid_t correlationId,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *salt,
    void **pkey);

void MSCRYPT_CLIENT_pfx_close(
    MSCRYPT_PFX_CTX *keyCtx);

void MSCRYPT_SERVER_pfx_free(
    void *pkey);

void MSCRYPT_SERVER_pfx_up_ref(
    void *pkey);

int MSCRYPT_CLIENT_rsa_private_encrypt(
    MSCRYPT_PFX_CTX *keyCtx,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding);

int MSCRYPT_SERVER_rsa_private_encrypt(
    const uuid_t correlationId,
    void *pkey,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding);

int MSCRYPT_CLIENT_rsa_private_decrypt(
    MSCRYPT_PFX_CTX *keyCtx,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding);

int MSCRYPT_SERVER_rsa_private_decrypt(
    const uuid_t correlationId,
    void *pkey,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding);

int MSCRYPT_CLIENT_ecdsa_sign(
    MSCRYPT_PFX_CTX *keyCtx,
    int type,
    const unsigned char *dgst,
    int dlen,
    unsigned char *sig,
    unsigned int siglen,
    unsigned int *outlen);

int MSCRYPT_SERVER_ecdsa_sign(
    const uuid_t correlationId,
    void *pkey,
    int type,
    const unsigned char *dgst,
    int dlen,
    unsigned char *sig,
    unsigned int siglen,
    unsigned int *outlen);

int MSCRYPT_SERVER_create_self_sign_pfx(
    const uuid_t correlationId,
    int mscryptFlags,
    const char *confStr,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // MSCRYPT_free()
    char **outPfxSalt);                 // MSCRYPT_free()

// The pemCert consists of the end certificate followed by
// 1 or more CA certificates
int MSCRYPT_SERVER_replace_pfx_certs(
    const uuid_t correlationId,
    int mscryptFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inSalt,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    int *outPfxLength,
    unsigned char **outPfxBytes,    // MSCRYPT_free()
    char **outSalt);                // MSCRYPT_free()


#ifdef  __cplusplus
}
#endif

#endif /* HEADER_MSCRYPTP_H */
