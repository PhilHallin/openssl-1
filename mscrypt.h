#ifndef HEADER_MSCRYPT_H
# define HEADER_MSCRYPT_H


# ifdef MSCRYPT_TEST_WINDOWS
typedef unsigned char uuid_t[16];
# else
#   include <uuid/uuid.h>
# endif

# include <openssl/x509.h>

#ifdef  __cplusplus
extern "C" {
#endif

//
// MSCRYPT memory functions
//

void* MSCRYPT_zalloc(
    size_t num);

void* MSCRYPT_realloc(
    void *mem,
    size_t num);

void MSCRYPT_free(
    void *mem);

void MSCRYPT_clear_free(
    void *mem,
    size_t num);

void MSCRYPT_clear_free_string(
    char *str);

void MSCRYPT_cleanse(
    void *mem,
    size_t num);

char *MSCRYPT_strdup(
    const char *str);


// MSCRYPT Flags
# define MSCRYPT_EXCLUDE_ROOT_FLAG                          0x00000001
# define MSCRYPT_EXCLUDE_EXTRA_CA_FLAG                      0x00000002
# define MSCRYPT_EXCLUDE_END_FLAG                           0x00000004
# define MSCRYPT_IGNORE_DEPTH_ZERO_SELF_SIGNED_ERROR_FLAG   0x00000008

typedef struct MSCRYPT_shared_mem_st MSCRYPT_SHARED_MEM;

// For an error, returns NULL.
MSCRYPT_SHARED_MEM *MSCRYPT_open_shared_mem(
    const uuid_t correlationId,
    int memLength,
    unsigned char **memBytes);

void MSCRYPT_close_shared_mem(
    MSCRYPT_SHARED_MEM *sharedMem);

#define MSCRYPT_CERT_FORMAT_DER         1
#define MSCRYPT_CERT_FORMAT_PEM         2
#define MSCRYPT_CERT_FORMAT_SST         3
#define MSCRYPT_CERT_FORMAT_CTL         4

// Return:
//  +1 - Success with all certificates imported.
//  -1 - Partial Success. Imported at least one certificate. Failed to
//       import one or more certificates.
//   0 - Error, unable to import any certificates.
int MSCRYPT_import_trusted_certs(
    const uuid_t correlationId,
    MSCRYPT_SHARED_MEM *sharedMem, // Optional
    int certFormat,
    int certLength,
    const unsigned char *certBytes);

// Return:
//  +1 - Success with all certificates removed.
//  -1 - Partial Success. Removed at least one certificate. Failed to
//       remove one or more certificates.
//   0 - Error, unable to remove any certificates.
int MSCRYPT_remove_trusted_certs(
    const uuid_t correlationId,
    MSCRYPT_SHARED_MEM *sharedMem,  // Optional
    int certFormat,
    int certLength,
    const unsigned char *certBytes);

// Return:
//  +1 - Success with all certificates imported.
//  -1 - Partial Success. Imported at least one certificate. Failed to
//       import one or more certificates.
//   0 - Error, unable to import any certificates.
//
// For certFormat == MSCRYPT_CERT_FORMAT_CTL, imports disallowed CTL
int MSCRYPT_import_disallowed_certs(
    const uuid_t correlationId,
    MSCRYPT_SHARED_MEM *sharedMem,  // Optional
    int certFormat,
    int certLength,
    const unsigned char *certBytes);

// Return:
//  +1 - Success with all certificates removed.
//  -1 - Partial Success. Removed at least one certificate. Failed to
//       remove one or more certificates.
//   0 - Error, unable to remove any certificates.
//
// For certFormat == MSCRYPT_CERT_FORMAT_CTL, removes disallowed CTL
int MSCRYPT_remove_disallowed_certs(
    const uuid_t correlationId,
    MSCRYPT_SHARED_MEM *sharedMem,  // Optional
    int certFormat,
    int certLength,
    const unsigned char *certBytes);

// Return:
//  1 - Certificate is disallowed.
//  0 - Certificate not found in the disallowed certificates directory.
int MSCRYPT_is_disallowed_cert(
    const uuid_t correlationId,
    X509 *cert);

typedef struct MSCRYPT_cert_dir_st MSCRYPT_CERT_DIR;

// Returns directory handle or NULL on error.
MSCRYPT_CERT_DIR *MSCRYPT_open_trusted_cert_dir(
    const uuid_t correlationId,
    int mscryptFlags);

MSCRYPT_CERT_DIR *MSCRYPT_open_disallowed_cert_dir(
    const uuid_t correlationId,
    int mscryptFlags);

// Return:
//  +1 - Success with *cert updated
//  -1 - No more certs. *cert is set to NULL.
//   0 - Error
int MSCRYPT_read_cert_dir(
    MSCRYPT_CERT_DIR *certDir,
    X509 **cert);               // X509_free()

void MSCRYPT_close_cert_dir(
    MSCRYPT_CERT_DIR *certDir);

typedef struct MSCRYPT_ctl_dir_st MSCRYPT_CTL_DIR;

// Returns directory handle or NULL on error.
MSCRYPT_CTL_DIR *MSCRYPT_open_disallowed_ctl_dir(
    const uuid_t correlationId,
    int mscryptFlags);

// Return:
//  +1 - Success with *ctlLength and *ctlBytes updated
//  -1 - No more ctls. *ctlLength is set to 0 and *ctlBytes is set to NULL.
//   0 - Error
int MSCRYPT_read_ctl_dir(
    MSCRYPT_CTL_DIR *ctlDir,
    int *ctlLength,
    unsigned char **ctlBytes);  // MSCRYPT_free()

void MSCRYPT_close_ctl_dir(
    MSCRYPT_CTL_DIR *ctlDir);


// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int MSCRYPT_import_pfx(
    const uuid_t correlationId,
    int mscryptFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *password,             // Optional
    int *verifyChainError,
    int *pfxLength,
    unsigned char **pfxBytes,         // MSCRYPT_clear_free()
    char **salt);                     // MSCRYPT_clear_free_string()

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int MSCRYPT_import_pfx_to_key_id(
    const uuid_t correlationId,
    int mscryptFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *password,             // Optional
    int *verifyChainError,
    char **keyId);                    // MSCRYPT_clear_free_string()

int MSCRYPT_format_pfx_engine_key_id(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    const char *salt,
    char **keyId);                    // MSCRYPT_clear_free_string()


int MSCRYPT_parse_pfx_engine_key_id(
    const uuid_t correlationId,
    const char *keyId,
    int *pfxLength,
    unsigned char **pfxBytes,         // MSCRYPT_clear_free()
    char **salt);                     // Optional, MSCRYPT_clear_free_string()

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int MSCRYPT_build_cert_chain_from_pfx(
    const uuid_t correlationId,
    int mscryptFlags,
    int pfxLength,
    const unsigned char *pfxBytes,
    int *verifyChainError,
    int *pemCertLength,              // Excludes NULL terminator
    char **pemCert);                 // MSCRYPT_free()                   

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int MSCRYPT_build_cert_chain_from_key_id(
    const uuid_t correlationId,
    int mscryptFlags,
    const char *keyId,
    int *verifyChainError,
    int *pemCertLength,              // Excludes NULL terminator
    char **pemCert);                 // MSCRYPT_free()                   


typedef struct MSCRYPT_verify_cert_ctx_st MSCRYPT_VERIFY_CERT_CTX;

MSCRYPT_VERIFY_CERT_CTX *MSCRYPT_create_verify_cert_ctx(
    const uuid_t correlationId);

void MSCRYPT_free_verify_cert_ctx(
    MSCRYPT_VERIFY_CERT_CTX *ctx);

typedef int (*MSCRYPT_PFN_VERIFY_CERT_CALLBACK)(
    const uuid_t correlationId,
    X509_STORE_CTX *storeCtx,
    int *verifyChainError,
    void *arg);

int MSCRYPT_register_verify_cert_callback(
    MSCRYPT_VERIFY_CERT_CTX *ctx,
    MSCRYPT_PFN_VERIFY_CERT_CALLBACK callback,
    void *arg);

void MSCRYPT_set_verify_cert_param(
    MSCRYPT_VERIFY_CERT_CTX *ctx,
    const X509_VERIFY_PARAM *param);


// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to build chain
//
// Following mscryptFlags can be set to exclude certificates in the
// returned STACK_OF(X509) **chain.
//  #define MSCRYPT_EXCLUDE_ROOT_FLAG                          0x00000001
//  #define MSCRYPT_EXCLUDE_EXTRA_CA_FLAG                      0x00000002
//  #define MSCRYPT_EXCLUDE_END_FLAG                           0x00000004
//
// Following mscryptFlags can be set to allow self signed certificate
//  #define MSCRYPT_IGNORE_DEPTH_ZERO_SELF_SIGNED_ERROR_FLAG   0x00000008
int MSCRYPT_verify_cert2(
    MSCRYPT_VERIFY_CERT_CTX *ctx,   // Optional
    int mscryptFlags,
    X509 *cert,
    STACK_OF(X509) *ca,             // Optional
    int *verifyChainError,
    STACK_OF(X509) **chain);        // Optional

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, other errors, such as, invalid input certificate.
//
// Following mscryptFlags can be set to exclude certificates in the
// returned PEM chain
//  #define MSCRYPT_EXCLUDE_ROOT_FLAG                          0x00000001
//  #define MSCRYPT_EXCLUDE_EXTRA_CA_FLAG                      0x00000002
//  #define MSCRYPT_EXCLUDE_END_FLAG                           0x00000004
//
// Following mscryptFlags can be set to allow self signed certificate
//  #define MSCRYPT_IGNORE_DEPTH_ZERO_SELF_SIGNED_ERROR_FLAG   0x00000008
int MSCRYPT_verify_cert(
    MSCRYPT_VERIFY_CERT_CTX *ctx,       // Optional
    int mscryptFlags,
    int certFormat,                     // Only DER and PEM
    int certLength,
    const unsigned char *certBytes,
    int *verifyChainError,
    int *pemChainLength,                // Optional, excludes NULL terminator
    char **pemChain);                   // Optional, MSCRYPT_free()

int MSCRYPT_load_pem_cert(
    const uuid_t correlationId,
    int certLength,
    const unsigned char *certBytes,
    X509 **cert,
    STACK_OF(X509) **ca);

// Returns 1 for success and 0 for an error
int MSCRYPT_create_self_sign_pfx(
    const uuid_t correlationId,
    int mscryptFlags,
    const char *confStr,
    int *pfxLength,
    unsigned char **pfxBytes,           // MSCRYPT_clear_free()
    char **salt);                       // MSCRYPT_clear_free_string()

// Returns 1 for success and 0 for an error
int MSCRYPT_create_self_sign_pfx_to_key_id(
    const uuid_t correlationId,
    int mscryptFlags,
    const char *confStr,
    char **keyId);                    // MSCRYPT_clear_free_string()

// Returns 1 for success and 0 for an error
// The pemCert consists of the end certificate followed by
// 1 or more CA certificates
int MSCRYPT_replace_pfx_certs(
    const uuid_t correlationId,
    int mscryptFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inSalt,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // MSCRYPT_clear_free()
    char **outSalt);                    // MSCRYPT_clear_free_string()

// Returns 1 for success and 0 for an error
int MSCRYPT_replace_key_id_certs(
    const uuid_t correlationId,
    int mscryptFlags,
    const char *inKeyId,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    char **outKeyId);                   // MSCRYPT_clear_free_string()

// Returns 1 for success and 0 for an error
int MSCRYPT_replace_key_id_certs2(
    const uuid_t correlationId,
    int mscryptFlags,
    const char *inKeyId,
    X509 *cert,
    STACK_OF(X509) *ca,                 // Optional
    char **outKeyId);                   // MSCRYPT_clear_free_string()

EVP_PKEY *MSCRYPT_load_engine_private_key(
    const uuid_t correlationId,
    const char *engineName,
    const char *engineKeyId);

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_MSCRYPT_H */


