#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/conf.h>
#include "mscryptp.h"

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
    unsigned char **pfxBytes,         // MSCRYPT_free()
    char **salt)                      // MSCRYPT_free()
{
    return MSCRYPT_CLIENT_import_pfx(
        correlationId,
        mscryptFlags,
        inPfxLength,
        inPfxBytes,
        password,
        verifyChainError,
        pfxLength,
        pfxBytes,
        salt);
}

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
    char **keyId)                     // MSCRYPT_free()
{
    int ret = 0;
    int outPfxLength = 0;
    unsigned char *outPfxBytes = NULL;  // MSCRYPT_free()
    char *salt = NULL;                  // MSCRYPT_clear_free_string()

    *keyId = NULL;

    ret = MSCRYPT_import_pfx(
        correlationId,
        mscryptFlags,
        inPfxLength,
        inPfxBytes,
        password,
        verifyChainError,
        &outPfxLength,
        &outPfxBytes,
        &salt);
    if (ret != 0) {
        if (!MSCRYPT_format_pfx_engine_key_id(
                correlationId,
                outPfxLength,
                outPfxBytes,
                salt,
                keyId)) {
            ret = 0;
        }
    }

    MSCRYPT_free(outPfxBytes);
    MSCRYPT_clear_free_string(salt);
    return ret;
}

// Returns BIO_s_mem().
static BIO *_create_pfx(
    const uuid_t correlationId,
    EVP_PKEY *key,
    X509 *cert,
    STACK_OF(X509) *ca,               // Optional
    const char *password,
    int *pfxLength,
    unsigned char **pfxBytes)         // Don't free
{
    const char *title = MSCRYPTP_HELPER_PFX_TITLE;
    const char *loc = "";
    int ret = 0;
    PKCS12 *p12 = NULL;
    BIO *bioPfx = NULL;

    ERR_clear_error();

    p12 = PKCS12_create(
        password,
        NULL,                                   // name
        key,
        cert,
        ca,
//        NID_pbe_WithSHA1And3_Key_TripleDES_CBC, // key_pbe
        NID_aes_256_cbc,                        // key_pbe
        -1,                                     // cert_pbe, -1 => no encryption
        PKCS12_DEFAULT_ITER,                    // iter
        -1,                                     // mac_iter
        0);                                     // keytype
    if (p12 == NULL) {
        loc = "PKCS12_create";
        goto openSslErr;
    }

    if (!PKCS12_set_mac(
            p12,
            password,
            -1,                                 // passlen, -1 => NULL terminated
            NULL,                               // salt
            0,                                  // saltlen
            PKCS12_DEFAULT_ITER,                // iter
            EVP_sha256())) {                    // const EVP_MD* md_type, NULL => sha1
        loc = "PKCS12_set_mac";
        goto openSslErr;
    }

    bioPfx = BIO_new(BIO_s_mem());
    if (bioPfx == NULL) {
        loc = "BIO_new";
        goto openSslErr;
    }

    if (!i2d_PKCS12_bio(bioPfx, p12)) {
        loc = "i2d_PKCS12_bio";
        goto openSslErr;
    }

    *pfxLength = (int) BIO_get_mem_data(bioPfx, pfxBytes);
    if (*pfxLength == 0 || *pfxBytes == NULL) {
        loc = "BIO_get_mem_data";
        goto openSslErr;
    }

    ret = 1;
end:
    if (!ret) {
        BIO_free(bioPfx);
        bioPfx = NULL;
        *pfxLength = 0;
        *pfxBytes = NULL;
    }
    PKCS12_free(p12);
    return bioPfx;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}


// Format:  <Salt> ":" <Base64 PFX>
int MSCRYPT_format_pfx_engine_key_id(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    const char *salt,
    char **keyId)                   // MSCRYPT_free()
{
    const char *title = MSCRYPTP_HELPER_PFX_TITLE;
    int ret = 0;
    int saltLength = (int) strlen(salt);
    int base64Length = MSCRYPTP_BASE64_ENCODE_LENGTH(pfxLength); // includes NULL terminator
    int idLength = saltLength + 1 + base64Length;
    char *id = NULL;                // MSCRYPT_free()
    int encodeLength;

    ERR_clear_error();

    id = (char *) MSCRYPT_zalloc(idLength);
    if (id == NULL) {
        goto end;
    }

    memcpy(id, salt, saltLength);
    id[saltLength] = ':';
    encodeLength = EVP_EncodeBlock(id + saltLength + 1, pfxBytes, pfxLength);
    if (encodeLength != base64Length - 1) {
        MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, "EVP_EncodeBlock",
            "length: %d expected: %d", encodeLength, base64Length - 1);
        MSCRYPT_free(id);
        id = NULL;
        goto end;
    }
    
    ret = 1;
end:
    *keyId = id;
    return ret;
}

// Format:  <Salt> ":" <Base64 PFX>
int MSCRYPT_parse_pfx_engine_key_id(
    const uuid_t correlationId,
    const char *keyId,
    int *pfxLength,
    unsigned char **pfxBytes,         // MSCRYPT_free()
    char **salt)                      // Optional, MSCRYPT_free()
{
    const char *title = MSCRYPTP_HELPER_PFX_TITLE;
    int ret = 0;
    BIO *fileBio = NULL;
    const char *pfxStr = NULL;  // Don't free
    size_t saltLength;

    *pfxLength = 0;
    *pfxBytes = NULL;
    if (salt) {
        *salt = NULL;
    }

    ERR_clear_error();

    if (strncmp(keyId, "file:", 5) == 0) {
        char *fileString = NULL;        // don't free
        fileBio = MSCRYPTP_read_file_string(correlationId, keyId + 5, 0, &fileString);
        if (fileBio == NULL) {
            goto end;
        }
        keyId = fileString;
    } else {
        int onlyFilename = 0;
        char *fileString = NULL;        // don't free

        // ":" is used for salt separator. SaltLength > base64(16 bytes)
        pfxStr = strchr(keyId, ':');
        if (pfxStr == NULL || (pfxStr - keyId) <= 20) {
            onlyFilename = 1;
        }

        fileBio = MSCRYPTP_read_file_string(correlationId, keyId, !onlyFilename, &fileString);
        if (fileBio == NULL) {
            if (onlyFilename) {
                goto end;
            }
        } else {
            keyId = fileString;
        }
    }

    pfxStr = strchr(keyId, ':');
    if (pfxStr == NULL) {
        MSCRYPTP_trace_log_error(correlationId, 0, title, "strchr", "No salt");
        goto end;
    }

    saltLength = pfxStr - keyId;
    pfxStr++;
    if (saltLength == 0) {
        MSCRYPTP_trace_log_error(correlationId, 0, title, "SaltLength", "Zero length salt");
        goto end;
    }

    *pfxLength = MSCRYPTP_base64_decode(correlationId, pfxStr, pfxBytes);
    if (*pfxLength <= 0) {
        goto end;
    }

    if (salt) {
        *salt = (char *) MSCRYPT_zalloc(saltLength + 1);
        if (*salt == NULL) {
            goto end;
        }
        memcpy(*salt, keyId, saltLength);
    }

    ret = 1;
end:
    if (!ret) {
        MSCRYPT_free(*pfxBytes);
        *pfxBytes = NULL;
        *pfxLength = 0;
    }

    BIO_free(fileBio);
    return ret;
}

static int _parse_bags(
    const STACK_OF(PKCS12_SAFEBAG) *bags, 
    X509 **cert,
    STACK_OF(X509) *ocerts);

static int _parse_bag(
    PKCS12_SAFEBAG *bag, 
    X509 **cert,
    STACK_OF(X509) *ocerts)
{
    X509 *x509 = NULL;
    const ASN1_TYPE *attrib = NULL;
    ASN1_OCTET_STRING *lkid = NULL;

    if ((attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID)))
        lkid = attrib->value.octet_string;

    switch (PKCS12_SAFEBAG_get_nid(bag)) {
    case NID_certBag:
        if (PKCS12_SAFEBAG_get_bag_nid(bag) != NID_x509Certificate)
            return 1;
        if ((x509 = PKCS12_SAFEBAG_get1_cert(bag)) == NULL)
            return 0;

        if (lkid) {
            if (!*cert) 
                *cert = x509;
            else
                X509_free(x509);

            return 1;
        }

        if (!sk_X509_push(ocerts, x509)) {
            X509_free(x509);
            return 0;
        }

        break;

    case NID_safeContentsBag:
        return _parse_bags(PKCS12_SAFEBAG_get0_safes(bag), cert, ocerts);

    default:
        return 1;
    }
    return 1;
}

static int _parse_bags(
    const STACK_OF(PKCS12_SAFEBAG) *bags, 
    X509 **cert,
    STACK_OF(X509) *ocerts)
{
    for (int i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        if (!_parse_bag(sk_PKCS12_SAFEBAG_value(bags, i),
                                 cert, ocerts)) {
            return 0;
        }
    }
    return 1;
}

int MSCRYPTP_load_pfx_certs(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    X509 **cert,
    STACK_OF(X509) **ca)        // Optional
{
    const char *title = MSCRYPTP_HELPER_PFX_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *in = NULL;
    PKCS12 *p12 = NULL;

    X509 *x = NULL;
    STACK_OF(X509) *ocerts = NULL;
    STACK_OF(PKCS7) *asafes = NULL;
    int i;

    *cert = NULL;

    ERR_clear_error();
    
    /* Allocate stack for other certificates */
    ocerts = sk_X509_new_null();
    if (!ocerts) {
        goto openSslErr;
    }

    in = BIO_new_mem_buf(pfxBytes, pfxLength);
    if (in == NULL) {
        goto openSslErr;
    }

    p12 = d2i_PKCS12_bio(in, NULL);
    if (p12 == NULL) {
        loc = "d2i_PKCS12_bio";
        goto openSslErr;
    }

    if ((asafes = PKCS12_unpack_authsafes(p12)) == NULL) {
        loc = "PKCS12_unpack_authsafes";
        goto openSslErr;
    }

    for (i = 0; i < sk_PKCS7_num(asafes); i++) {
        STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
        PKCS7 *p7 = sk_PKCS7_value(asafes, i);
        int bagnid = OBJ_obj2nid(p7->type);

        if (bagnid == NID_pkcs7_data) {
            bags = PKCS12_unpack_p7data(p7);
        } else {
            continue;
        }
        if (!bags) {
            loc = "PKCS12_unpack_p7data";
            goto parseErr;
        }
        if (!_parse_bags(bags, cert, ocerts)) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            loc = "_parse_bags";
            goto parseErr;
        }
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    }

    if (!*cert) {
        loc = "NoCert";
        goto parseErr;
    }

    if (ca) {
        while ((x = sk_X509_pop(ocerts))) {
            if (!*ca) {
                *ca = sk_X509_new_null();
            }
            if (!*ca) {
                goto openSslErr;
            }
            if (!sk_X509_push(*ca, x)) {
                goto openSslErr;
            }
        }
    }

    ret = 1;
end:
    BIO_free(in);
    PKCS12_free(p12);
    sk_PKCS7_pop_free(asafes, PKCS7_free);
    X509_free(x);
    sk_X509_pop_free(ocerts, X509_free);

    if (!ret) {
        X509_free(*cert);
        *cert = NULL;
    }
    return ret;

parseErr:
    MSCRYPTP_trace_log_error(correlationId, 0, title, loc, "Parse PFX error");
    goto end;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

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
    char **pemCert)                  // MSCRYPT_free()                   
{
    int ret = 0;
    int chainRet = 0;
    uuid_t randId;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    STACK_OF(X509) *chain = NULL;
    MSCRYPT_VERIFY_CERT_CTX *ctx = NULL;    // MSCRYPT_free_verify_cert_ctx()

    *verifyChainError = 0;
    *pemCertLength = 0;
    *pemCert = NULL;

    if (correlationId == NULL) {
        RAND_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    ERR_clear_error();

    if (!MSCRYPTP_load_pfx_certs(
            correlationId,
            pfxLength,
            pfxBytes,
            &cert,
            &ca)) {
        goto end;
    }

    ctx = MSCRYPT_create_verify_cert_ctx(correlationId);
    if (ctx == NULL) {
        goto end;
    }

    chainRet = MSCRYPT_verify_cert2(
        ctx,
        mscryptFlags | MSCRYPT_IGNORE_DEPTH_ZERO_SELF_SIGNED_ERROR_FLAG,
        cert,
        ca,
        verifyChainError,
        &chain);
    if (chainRet == 0) {
        goto end;
    }

    if (!MSCRYPTP_pem_from_certs(
            correlationId,
            NULL,                   // X509 *cert
            chain,
            pemCertLength,
            pemCert)) {
        goto end;
    }

    ret = chainRet;

end:
    X509_free(cert);
    sk_X509_pop_free(ca, X509_free);
    sk_X509_pop_free(chain, X509_free);
    MSCRYPT_free_verify_cert_ctx(ctx);
    return ret;
}

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
    char **pemCert)                  // MSCRYPT_free()                   
{
    int ret = 0;
    int pfxLength = 0;
    unsigned char *pfxBytes = NULL;     // MSCRYPT_free()

    *verifyChainError = 0;
    *pemCertLength = 0;
    *pemCert = NULL;

    ret = MSCRYPT_parse_pfx_engine_key_id(
        correlationId,
        keyId,
        &pfxLength,
        &pfxBytes,
        NULL);          // salt
    if (ret) {
        ret = MSCRYPT_build_cert_chain_from_pfx(
            correlationId,
            mscryptFlags,
            pfxLength,
            pfxBytes,
            verifyChainError,
            pemCertLength,                 // excludes NULL terminator
            pemCert);
    }

    MSCRYPT_free(pfxBytes);

    return ret;
}

#define MSCRYPT_PFX_SECRET_SALT_LENGTH  4
#define MSCRYPT_PFX_SECRET_KEY_LENGTH   32
#define MSCRYPT_PFX_SECRET_FILE_LENGTH  (MSCRYPT_PFX_SECRET_SALT_LENGTH + MSCRYPT_PFX_SECRET_KEY_LENGTH)

// First byte will always be nonzero for a secret that has been read
static unsigned char MSCRYPTP_pfxSecret[MSCRYPT_PFX_SECRET_FILE_LENGTH];

static int _read_pfx_secret_file(
    const uuid_t correlationId,
    const char *filename)
{
    const char *title = MSCRYPTP_PFX_SECRET_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *in = NULL;

    ERR_clear_error();

    in = BIO_new_file(filename, "rb");
    if (in == NULL) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != BIO_R_NO_SUCH_FILE) {
            loc = "BIO_new_file";
            goto openSslErr;
        }
        goto end;
    }

    if (BIO_read(in, MSCRYPTP_pfxSecret, sizeof(MSCRYPTP_pfxSecret)) != sizeof(MSCRYPTP_pfxSecret)) {
        loc = "BIO_read";
        goto openSslErr;
    }

    if (MSCRYPTP_pfxSecret[0] == 0) {
        loc = "Invalid Content";
        goto openSslErr;
    }

    ret = 1;

end:
    if (!ret) {
        MSCRYPTP_pfxSecret[0] = 0;
    }
    BIO_free(in);
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "filename: %s", filename);
    goto end;
}

static int _write_pfx_secret_file(
    const uuid_t correlationId,
    const char *filename)
{
    const char *title = MSCRYPTP_PFX_SECRET_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *out = NULL;
    unsigned char randBytes[MSCRYPT_PFX_SECRET_FILE_LENGTH];

    ERR_clear_error();

    if (!RAND_bytes(randBytes, sizeof(randBytes))) {
        loc = "RAND_bytes";
        goto openSslErr;
    }

    if (randBytes[0] == 0) {
        randBytes[0] = 1;
    }

    out = BIO_new_file(filename, "wb");
    if (out == NULL) {
        loc = "BIO_new_file";
        goto openSslErr;
    }

    if (BIO_write(out, randBytes, sizeof(randBytes)) != sizeof(randBytes)) {
        loc = "BIO_write";
        goto openSslErr;
    }
    BIO_flush(out);

    ret = 1;

end:
    BIO_free(out);
    MSCRYPT_cleanse(randBytes, sizeof(randBytes));
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "filename: %s", filename);
    goto end;
}

#define MSCRYPT_PFX_SECRET_SUB_PATH "private/pfx.0"

// OPENSSLDIR "/" "private/pfx.0"
// MSCRYPT_free() returned filename
static char *_get_pfx_secret_filename()
{
    const char *dir = MSCRYPTP_get_default_cert_area();
    size_t dirLength = strlen(dir);
    const char *subPath = MSCRYPT_PFX_SECRET_SUB_PATH;
    size_t subPathLength = strlen(subPath);
    size_t filenameLength = dirLength + 1 + subPathLength + 1;
    char *filename = (char *) MSCRYPT_zalloc(filenameLength);

    if (filename != NULL) {
        BIO_snprintf(filename, filenameLength, "%s/%s",
            dir, subPath);
    }

    return filename;
}

int MSCRYPTP_create_pfx_secret(
    const uuid_t correlationId)
{
    const char *title = MSCRYPTP_PFX_SECRET_TITLE;
    int ret = 0;
    char *filename = NULL;      // MSCRYPT_free()

    filename = _get_pfx_secret_filename();
    if (filename == NULL) {
        goto end;
    }

    if (_read_pfx_secret_file(correlationId, filename)) {
        MSCRYPTP_trace_log_para(correlationId, 0, title, "Using previously generated PFX secret",
            "secret: %s", filename);
        goto success;
    }

    if (_write_pfx_secret_file(correlationId, filename) &&
            _read_pfx_secret_file(correlationId, filename)) {
        MSCRYPTP_trace_log_para(correlationId, 0, title, "Generated PFX secret",
            "secret: %s", filename);
        goto success;
    }

    MSCRYPTP_trace_log_error_para(correlationId, 0, title, "Create PFX secret", "Failed",
        "secret: %s", filename);
    goto end;

success:
    ret = 1;

end:
    MSCRYPT_free(filename);
    return ret;
}

int MSCRYPTP_useTestPfxSecret;

// salt
//  t.<base64>  -- test salt
//  0.<base64>  -- persisted pfx secret
static int _generate_pfx_salt(
    const uuid_t correlationId,
    char **salt)    // MSCRYPT_free()
{
    const char *title = MSCRYPTP_PFX_SECRET_TITLE;
    const char *loc = "";
    int ret = 0;
    char versionChar = '?';
    unsigned char randBytes[MSCRYPT_PFX_SECRET_SALT_LENGTH + 16];
    unsigned char base64Bytes[MSCRYPTP_BASE64_ENCODE_LENGTH(MSCRYPT_PFX_SECRET_SALT_LENGTH + 16)];
    int saltLength = 2 + sizeof(base64Bytes);
    int encodeLength = 0;

    *salt = NULL;

    if (MSCRYPTP_useTestPfxSecret) {
        versionChar = 't';
        memset(randBytes, 0, MSCRYPT_PFX_SECRET_SALT_LENGTH);
    } else {
        versionChar = '0';
        memcpy(randBytes, MSCRYPTP_pfxSecret, MSCRYPT_PFX_SECRET_SALT_LENGTH);
    }

    ERR_clear_error();

    if (!RAND_bytes(
            randBytes + MSCRYPT_PFX_SECRET_SALT_LENGTH,
            sizeof(randBytes) - MSCRYPT_PFX_SECRET_SALT_LENGTH)) {
        loc = "RAND_bytes";
        goto openSslErr;
    }

    encodeLength = EVP_EncodeBlock(base64Bytes, randBytes, (int) sizeof(randBytes));
    if (encodeLength != (int) sizeof(base64Bytes) - 1) {
        MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, "EVP_EncodeBlock",
            "length: %d expected: %d", encodeLength, (int) sizeof(base64Bytes) - 1);
        goto end;
    }

    *salt = (char *) MSCRYPT_zalloc(saltLength);
    if (*salt == NULL) {
        goto end;
    }

    BIO_snprintf(*salt, saltLength, "%c.%s",
        versionChar,
        base64Bytes);

    ret = 1;

end:
    MSCRYPT_cleanse(randBytes, sizeof(randBytes));
    MSCRYPT_cleanse(base64Bytes, sizeof(base64Bytes));
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

static int _is_valid_pfx_salt(
    const uuid_t correlationId,
    const char *salt)
{
    const char *title = MSCRYPTP_PFX_SECRET_TITLE;
    const char *errStr = "";
    int ret = 0;
    size_t saltLength = strlen(salt);
    unsigned char *decoded = NULL;  // MSCRYPT_free()
    int decodedLength = 0;

    ERR_clear_error();

    // "0." <base64 salt>
    if (saltLength < 3 || salt[0] != '0') {
        errStr = "Invalid salt";
        goto err;
    }

    decodedLength = MSCRYPTP_base64_decode(correlationId, &salt[2], &decoded);
    if (decodedLength < MSCRYPT_PFX_SECRET_SALT_LENGTH) {
        errStr = "Invalid decoded salt";
        goto err;
    }

    if (MSCRYPTP_pfxSecret[0] == 0) {
        errStr = "PFX secret not created at service start";
        goto err;
    }

    if (memcmp(MSCRYPTP_pfxSecret, decoded, MSCRYPT_PFX_SECRET_SALT_LENGTH) != 0) {
        errStr = "Salt doesn't match PFX secret";
        goto err;
    }

    ret = 1;

end:
    MSCRYPT_clear_free_string(decoded);
    return ret;

err:
    MSCRYPTP_trace_log_error(correlationId, 0, title, NULL, errStr);
    goto end;
}


static const char *_testSecret = "hYda/Q8Sz0Xb+0D0rmRJFgq21TPBP0EKSOBJi+3Ea5Q=";

static int _generate_pfx_password_from_salt(
    const uuid_t correlationId,
    const char *salt,
    char **password)    // MSCRYPT_free()
{
    const char *title = MSCRYPTP_PFX_SECRET_TITLE;
    const char *loc = "";
    int ret = 0;
    unsigned char hmacBytes[EVP_MAX_MD_SIZE];
    const void *key = NULL;
    int keyLength = 0;
    int hmacLength = 0;
    int passwordLength = 0;
    int encodeLength = 0;

    *password = NULL;

    if (salt == NULL) {
        salt = "";
    }

    if (salt[0] == 't') {
        key = (const void *) _testSecret;
        keyLength = (int) strlen(_testSecret);
    } else {
        if (!_is_valid_pfx_salt(correlationId, salt))
            goto end;

        // Key follows the secret's salt
        key = (const void * ) &MSCRYPTP_pfxSecret[MSCRYPT_PFX_SECRET_SALT_LENGTH];
        keyLength = MSCRYPT_PFX_SECRET_KEY_LENGTH;
    }

    ERR_clear_error();

    if (HMAC(
            EVP_sha256(),
            key,
            keyLength,
            salt,
            (int) strlen(salt),
            hmacBytes,
            &hmacLength) == NULL || hmacLength != 32) {
        loc = "HMAC";
        goto openSslErr;
    }
            
    passwordLength = MSCRYPTP_BASE64_ENCODE_LENGTH(hmacLength);
    *password = (char *) MSCRYPT_zalloc(passwordLength);
    if (*password == NULL) {
        goto openSslErr;
    }

    encodeLength = EVP_EncodeBlock(*password, hmacBytes, hmacLength);
    if (encodeLength != passwordLength - 1) {
        MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, "EVP_EncodeBlock",
            "length: %d expected: %d", encodeLength, passwordLength - 1);
        MSCRYPT_clear_free_string(*password);
        *password = NULL;
        goto end;
    }

    ret = 1;

end:
    MSCRYPT_cleanse(hmacBytes, sizeof(hmacBytes));
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

static int _create_salted_pfx(
    const uuid_t correlationId,
    EVP_PKEY *key,
    X509 *cert,
    STACK_OF(X509) *ca,               // Optional
    int *outPfxLength,
    unsigned char **outPfxBytes,      // MSCRYPT_free()
    char **outPfxSalt)                // MSCRYPT_free()
{
    const char *title = MSCRYPTP_PFX_SECRET_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *bioOutPfx = NULL;
    char *outSalt = NULL;
    int outSaltLength = 0;
    char *password = NULL;
    int outLength = 0;
    unsigned char *outBytes = NULL;         // don't free

    *outPfxLength = 0;
    *outPfxBytes = NULL;
    *outPfxSalt = NULL;

    if (!_generate_pfx_salt(correlationId, &outSalt)) {
        goto end;
    }

    if (!_generate_pfx_password_from_salt(correlationId, outSalt, &password)) {
        goto end;
    }

    bioOutPfx = _create_pfx(
        correlationId,
        key,
        cert,
        ca,
        password,
        &outLength,
        &outBytes);           // Don't free
    if (bioOutPfx == NULL) {
        goto end;
    }

    *outPfxBytes = (unsigned char *) MSCRYPT_zalloc(outLength);
    if (*outPfxBytes == NULL) {
        goto openSslErr;
    }

    memcpy(*outPfxBytes, outBytes, outLength);
    *outPfxLength = outLength;

    outSaltLength = (int) strlen(outSalt) + 1;
    *outPfxSalt = outSalt;
    outSalt = NULL;

    ret = 1;

end:
    MSCRYPT_clear_free_string(outSalt);
    MSCRYPT_clear_free_string(password);
    BIO_free(bioOutPfx);

    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *outVerifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int MSCRYPT_SERVER_import_pfx(
    const uuid_t correlationId,
    int mscryptFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inPassword,             // optional
    int *verifyChainError,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // MSCRYPT_free()
    char **outPfxSalt)                  // MSCRYPT_free()
{
    const char *title = MSCRYPTP_IMPORT_PFX_TITLE;
    const char *loc = "";
    int ret = 0;
    int buildPfxCaRet = 0;
    BIO *bioInPfx = NULL;
    PKCS12 *inP12 = NULL;
    EVP_PKEY *inPfxPkey = NULL;
    X509 *inPfxCert = NULL;
    STACK_OF(X509) *inPfxCa = NULL;
    STACK_OF(X509) *outPfxCa = NULL;
    MSCRYPT_VERIFY_CERT_CTX *ctx = NULL;    // MSCRYPT_free_verify_cert_ctx()

    *verifyChainError = 0;
    *outPfxLength = 0;
    *outPfxBytes = NULL;
    *outPfxSalt = NULL;

    ERR_clear_error();

    bioInPfx = BIO_new_mem_buf(inPfxBytes, inPfxLength);
    if (bioInPfx == NULL) {
        goto openSslErr;
    }

    inP12 = d2i_PKCS12_bio(bioInPfx, NULL);
    if (inP12 == NULL) {
        loc = "d2i_PKCS12_bio";
        goto openSslErr;
    }

    if (!PKCS12_parse(inP12, inPassword, &inPfxPkey, &inPfxCert, &inPfxCa)) {
        loc = "PKCS12_parse";
        goto openSslErr;
    }

    if (inPfxCert == NULL) {
        MSCRYPTP_trace_log_error(correlationId, 0, title, "AfterPKCS12_parse", "No end certificate in PFX");
        goto end;
    }

    ctx = MSCRYPT_create_verify_cert_ctx(correlationId);
    if (ctx == NULL) {
        goto end;
    }

    buildPfxCaRet = MSCRYPT_verify_cert2(
        ctx,
        MSCRYPT_EXCLUDE_END_FLAG |
            MSCRYPT_IGNORE_DEPTH_ZERO_SELF_SIGNED_ERROR_FLAG |
            (mscryptFlags & MSCRYPT_EXCLUDE_EXTRA_CA_FLAG),
        inPfxCert,
        inPfxCa,
        verifyChainError,
        &outPfxCa);
    if (buildPfxCaRet == 0) {
        goto end;
    }

    if (!_create_salted_pfx(
            correlationId,
            inPfxPkey,
            inPfxCert,
            outPfxCa,
            outPfxLength,
            outPfxBytes,        // MSCRYPT_free()
            outPfxSalt)) {      // MSCRYPT_free()
        goto end;
    }

    ret = buildPfxCaRet;
end:
    EVP_PKEY_free(inPfxPkey);
    X509_free(inPfxCert);
    sk_X509_pop_free(inPfxCa, X509_free);
    sk_X509_pop_free(outPfxCa, X509_free);
    PKCS12_free(inP12);
    BIO_free(bioInPfx);
    MSCRYPT_free_verify_cert_ctx(ctx);

    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}


int MSCRYPT_SERVER_pfx_open(
    const uuid_t correlationId,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *salt,
    void **pkey)
{
    const char *title = MSCRYPTP_OPEN_PFX_TITLE;
    const char *loc = "";
    int ret = 0;
    char *password = NULL;    // MSCRYPT_clear_free_string()
    BIO *bioPfx = NULL;
    PKCS12 *p12 = NULL;
    X509 *parse_cert = NULL;

    *pkey = NULL;

    ERR_clear_error();

    if (!_generate_pfx_password_from_salt(correlationId, salt, &password)) {
        goto end;
    }

    bioPfx = BIO_new_mem_buf(inPfxBytes, inPfxLength);
    if (bioPfx == NULL) {
        goto openSslErr;
    }

    p12 = d2i_PKCS12_bio(bioPfx, NULL);
    if (p12 == NULL) {
        loc = "d2i_PKCS12_bio";
        goto openSslErr;
    }

    if (!PKCS12_parse(p12, password, (EVP_PKEY **) pkey, &parse_cert, NULL)) {
        loc = "PKCS12_parse";
        goto openSslErr;
    }

    ret = 1;

end:
    MSCRYPT_clear_free_string(password);
    BIO_free(bioPfx);
    PKCS12_free(p12);
    X509_free(parse_cert);

    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

void MSCRYPT_SERVER_pfx_free(
    void *pkey)
{
    EVP_PKEY_free((EVP_PKEY *) pkey);
}

void MSCRYPT_SERVER_pfx_up_ref(
    void *pkey)
{
    EVP_PKEY_up_ref((EVP_PKEY *) pkey);
}


int MSCRYPT_SERVER_rsa_private_encrypt(
    const uuid_t correlationId,
    void *pkey,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding)
{
    const char *title = MSCRYPTP_RSA_ENCRYPT_TITLE;
    int ret = -1;
    EVP_PKEY *evp_pkey = (EVP_PKEY *) pkey;

    ERR_clear_error();

    if (EVP_PKEY_id(evp_pkey) == EVP_PKEY_RSA) {
        RSA *rsa = EVP_PKEY_get0_RSA(evp_pkey);        // get0 doesn't up_ref

        if (rsa == NULL) {
            MSCRYPTP_trace_log_error(correlationId, 0, title, "get0_RSA", "Not RSA");
        } else {
            int sigLen = RSA_size(rsa);
            if (tlen < sigLen) {
                MSCRYPTP_trace_log_error_para(correlationId, 0, title, "SigLength", "Invalid length",
                    "Length: %d Expected: %d", tlen, sigLen);
            } else {
                ret = RSA_private_encrypt(flen, from, to, rsa, padding);
                if (ret <= 0) {
                    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, "RSA_private_encrypt");
                }
            }
        }
    } else {
        MSCRYPTP_trace_log_error(correlationId, 0, title, "KeyType", "Not RSA");
    }

    return ret;
}
    


int MSCRYPT_SERVER_rsa_private_decrypt(
    const uuid_t correlationId,
    void *pkey,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding)
{
    const char *title = MSCRYPTP_RSA_DECRYPT_TITLE;
    int ret = -1;
    EVP_PKEY *evp_pkey = (EVP_PKEY *) pkey;

    ERR_clear_error();

    if (EVP_PKEY_id(evp_pkey) == EVP_PKEY_RSA) {
        RSA *rsa = EVP_PKEY_get0_RSA(evp_pkey);        // get0 doesn't up_ref

        if (rsa == NULL) {
            MSCRYPTP_trace_log_error(correlationId, 0, title, "get0_RSA", "Not RSA");
        } else {
            int decryptLen = RSA_size(rsa);
            if (tlen < decryptLen) {
                MSCRYPTP_trace_log_error_para(correlationId, 0, title, "DecryptLength", "Invalid length",
                    "Length: %d Expected: %d", tlen, decryptLen);
            } else {
                ret = RSA_private_decrypt(flen, from, to, rsa, padding);
                if (ret <= 0) {
                    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, "RSA_private_decrypt");
                }
            }
        }
    } else {
        MSCRYPTP_trace_log_error(correlationId, 0, title, "KeyType", "Not RSA");
    }

    return ret;
}

int MSCRYPT_SERVER_ecdsa_sign(
    const uuid_t correlationId,
    void *pkey,
    int type,
    const unsigned char *dgst,
    int dlen,
    unsigned char *sig,
    unsigned int siglen,
    unsigned int *outlen)
{
    const char *title = MSCRYPTP_ECC_SIGN_TITLE;
    int ret = 0;
    EVP_PKEY *evp_pkey = (EVP_PKEY *) pkey;

    *outlen = 0;
    ERR_clear_error();

    if (EVP_PKEY_id(evp_pkey) == EVP_PKEY_EC) {
        EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(evp_pkey);   // get0 doesn't up_ref
        if (eckey == NULL) {
            MSCRYPTP_trace_log_error(correlationId, 0, title, "get0_EC_KEY", "Not ECC");
        } else {
            int ecdsaSigLen = ECDSA_size(eckey);
            if ((int) siglen < ecdsaSigLen) {
                MSCRYPTP_trace_log_error_para(correlationId, 0, title, "SigLength", "Invalid length",
                    "Length: %d Expected: %d", siglen, ecdsaSigLen);
            } else {
                ret = ECDSA_sign(type, dgst, dlen, sig, outlen, eckey);
                if (!ret) {
                    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, "ECDSA_sign");
                }
            }
        }
    } else {
        MSCRYPTP_trace_log_error(correlationId, 0, title, "KeyType", "Not ECC");
    }

    return ret;
}

//
// MSCRYPT_SERVER_create_self_sign_pfx NCONF internal functions
//

/*

#
# rsa/ecc self_sign conf example
#
# No defaults. All names must be specified.
#

[self_sign]
key_type = rsa             # or ecc

# Set the following for rsa
rsa_bits = 2048
rsa_exp = 0x10001          # also 0x3
rsa_padding = 1            # 1 - RSA_PKCS1_PADDING 6 - RSA_PKCS1_PSS_PADDING

# Set the following for ecc
# "openssl ecparam -list_curves" for complete
ecc_curve = prime256v1     # also secp384r1 with sha384

sign_digest = sha256
days = 365
distinguished_name = dn
x509_extensions = v3_ext

[dn]
C = US
ST = Washington
L = Redmond
O = "Microsoft Corporation"

# Must prefix with "x." so the section names are unique.
# The "x." prefix is removed before calling X509_NAME_add_entry_by_txt
1.CN = "MSCrypt Test"
2.CN = "MSCrypt Test Key"

# Must prefix OID names with "x.". The "x." prefix is
# prepended to ensure a unique name in the section.
# The "x." prefix is removed before calling X509_NAME_add_entry_by_txt.
# In the following, "a." and "b." will be removed.
a.2.5.4.3 = "first CN OID"
b.2.5.4.3 = "second CN OID"

# Multi-value. Use "+" to indicate
11.CN = "Multi MSCrypt Test"
12.+CN = "Multi MSCrypt Test Rsa"
aa.+2.5.4.3 = "Multi first CN OID"
bb.+2.5.4.3 = "Multi second CN OID"

[v3_ext]
# see following for extension configuration
# https://www.openssl.org/docs/manmaster/man5/x509v3_config.html
basicConstraints = critical,CA:FALSE
extendedKeyUsage = critical,serverAuth,clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = @alt_names

[alt_names]
DNS.1 = test.mscrypt.microsoft.com
DNS.2 = key.test.mscrypt.microsoft.com

*/


static int _conf_load(
    const uuid_t correlationId,
    const char *confStr,
    CONF **conf)
{
    const char *title = MSCRYPTP_CREATE_SELF_SIGN_TITLE;
    const char *loc = "";
    long errorLine = -1;
    int ret = 0;
    BIO *in = NULL;

    ERR_clear_error();

    *conf = NCONF_new(NULL);
    if (*conf == NULL) {
        goto openSslErr;
    }

    in = BIO_new_mem_buf(confStr, (int) strlen(confStr));
    if (in == NULL) {
        goto openSslErr;
    }

    if (!NCONF_load_bio(*conf, in, &errorLine)) {
        loc = "NCONF_load_bio";
        goto openSslErr;
    }

    ret = 1;

end:
    BIO_free(in);
    if (!ret) {
        NCONF_free(*conf);
        *conf = NULL;
    }

    ERR_clear_error();
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "errorLine: %ld", errorLine);
    goto end;
}

static const char *_conf_get_string(
    const uuid_t correlationId,
    CONF *conf,
    const char *name)
{
    const char *title = MSCRYPTP_CREATE_SELF_SIGN_TITLE;
    char *str = NULL;

    ERR_clear_error();

    str = NCONF_get_string(conf, "self_sign", name);
    if (str == NULL) {
        MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, name);
    }

    ERR_clear_error();

    return (const char *) str;
}

static int _conf_get_number(
    const uuid_t correlationId,
    CONF *conf,
    const char *name,
    long *value)
{
    int ret = 0;
    const char *str = NULL; // don't free

    *value = 0;

    str = _conf_get_string(correlationId, conf, name);
    if (str == NULL) {
        goto end;
    }

    *value = strtol(str, NULL, 0);
    ret = 1;
end:
    return ret;
}

static STACK_OF(CONF_VALUE) *_conf_get_section(
    const uuid_t correlationId,
    CONF *conf,
    const char *section)
{
    const char *title = MSCRYPTP_CREATE_SELF_SIGN_TITLE;
    char *str = NULL;
    STACK_OF(CONF_VALUE) *values = NULL;

    ERR_clear_error();

    values = NCONF_get_section(conf, section);
    if (values == NULL) {
        MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, section);
    }

    ERR_clear_error();

    return values;
}

static EVP_PKEY *_conf_generate_rsa(
    const uuid_t correlationId,
    CONF *conf)
{
    const char *title = MSCRYPTP_CREATE_SELF_SIGN_TITLE;
    const char *loc = "";
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    long rsaBits = 0;
    long rsaExp = 0;
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;

    if (!_conf_get_number(correlationId, conf, "rsa_bits", &rsaBits) ||
            !_conf_get_number(correlationId, conf, "rsa_exp", &rsaExp) ||
            rsaBits <= 0 ||
            rsaExp <= 0) {
        goto end;
    }

    if (rsaBits > OPENSSL_RSA_MAX_MODULUS_BITS ||
            rsaBits < 2048) {
        MSCRYPTP_trace_log_error_para(correlationId, 0, title, "rsa_bits", "Invalid length",
            "rsa_bits: %ld", rsaBits);
        goto end;
    }

    rsa = RSA_new();
    bn = BN_new();
    pkey = EVP_PKEY_new();
    if (rsa == NULL || bn == NULL || pkey == NULL) {
        goto openSslErr;
    }

    if (!BN_set_word(bn, (BN_ULONG) rsaExp)) {
        loc = "BN_set_exp";
        goto openSslErr;
    }

    if (!RSA_generate_key_ex(
            rsa,
            (int) rsaBits,
            bn,
            NULL)) {            // BN_GENCB *cb
        loc = "RSA_generate_key_ex";
        goto openSslErr;
    }

    // The assign takes the rsa refCount
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        loc = "EVP_PKEY_assign_RSA";
        goto openSslErr;
    }
    rsa = NULL;

    ret = 1;

end:
    if (!ret) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    RSA_free(rsa);
    BN_free(bn);
    return pkey;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

static EVP_PKEY *_conf_generate_ecc(
    const uuid_t correlationId,
    CONF *conf)
{
    const char *title = MSCRYPTP_CREATE_SELF_SIGN_TITLE;
    const char *loc = "";
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EC_KEY *ecc = NULL;
    const char *eccCurve = NULL;    // don't free
    int nid = 0;

    eccCurve = _conf_get_string(correlationId, conf, "ecc_curve");
    if (eccCurve == NULL) {
        goto end;
    }

    /*
     * workaround for the SECG curve names secp192r1 and secp256r1 (which
     * are the same as the curves prime192v1 and prime256v1 defined in
     * X9.62)
     */
    if (strcmp(eccCurve, "secp192r1") == 0) {
        nid = NID_X9_62_prime192v1;
    } else if (strcmp(eccCurve, "secp256r1") == 0) {
        nid = NID_X9_62_prime256v1;
    } else {
        nid = OBJ_sn2nid(eccCurve);
    }

    if (nid == 0) {
        nid = EC_curve_nist2nid(eccCurve);
    }

    if (nid == 0) {
        MSCRYPTP_trace_log_error_para(correlationId, 0, title, "ecc_curve", "Unknown",
            "ecc_curve: %s", eccCurve);
        goto end;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        goto openSslErr;
    }

    ecc = EC_KEY_new_by_curve_name(nid);
    if (ecc == NULL) {
        loc = "EC_KEY_new_by_curve_name";
        goto end;
    }

    EC_KEY_set_asn1_flag(ecc, OPENSSL_EC_NAMED_CURVE);

    if (!EC_KEY_generate_key(ecc)) {
        loc = "EC_KEY_generate_key";
        goto openSslErr;
    }

    // The assign takes the ecc refCount
    if (!EVP_PKEY_assign_EC_KEY(pkey, ecc)) {
        loc = "EVP_PKEY_assign_EC_KEY";
        goto openSslErr;
    }
    ecc = NULL;

    ret = 1;

end:
    if (!ret) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    EC_KEY_free(ecc);
    return pkey;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}


static int _conf_get_key(
    const uuid_t correlationId,
    CONF *conf,
    X509 *cert,
    EVP_PKEY **pkey)
{
    const char *title = MSCRYPTP_CREATE_SELF_SIGN_TITLE;
    const char *keyType = NULL; // don't free
    int ret = 0;

    *pkey = NULL;

    keyType = _conf_get_string(correlationId, conf, "key_type");
    if (keyType == NULL) {
        goto end;
    }

    if (strcmp(keyType, "rsa") == 0) {
        *pkey = _conf_generate_rsa(correlationId, conf);
    } else if (strcmp(keyType, "ecc") == 0) {
        *pkey = _conf_generate_ecc(correlationId, conf);
    } else {
        MSCRYPTP_trace_log_error_para(correlationId, 0, title, "key_type", "Invalid",
            "Expected: rsa or ecc");
        goto end;
    }

    if (*pkey == NULL) {
        goto end;
    }

    ERR_clear_error();

    if (!X509_set_pubkey(cert, *pkey)) {
        MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, "X509_set_pubkey");
        goto end;
    }

    ret = 1;

end:
    if (!ret) {
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }

    return ret;
}

static int _conf_get_name(
    const uuid_t correlationId,
    CONF *conf,
    X509 *cert)
{
    const char *title = MSCRYPTP_CREATE_SELF_SIGN_TITLE;
    int ret = 0;
    const char *dnSect = NULL;              // don't free
    STACK_OF(CONF_VALUE) *dnValues = NULL;  // don't free
    X509_NAME *subj = NULL;                 // don't free

    dnSect = _conf_get_string(correlationId, conf, "distinguished_name");
    if (dnSect == NULL) {
        goto end;
    }

    dnValues = _conf_get_section(correlationId, conf, dnSect);
    if (dnValues == NULL) {
        goto end;
    }

    if (sk_CONF_VALUE_num(dnValues) == 0) {
        MSCRYPTP_trace_log_error(correlationId, 0, title, "Values", "Empty");
        goto end;
    }

    subj = X509_get_subject_name(cert);

    for (int i = 0; i < sk_CONF_VALUE_num(dnValues); i++) {
        CONF_VALUE *v = sk_CONF_VALUE_value(dnValues, i);
        const char *type = v->name;
        int mval = 0;   // 0 => not multi-valued

        ERR_clear_error();

        /*
         * Skip past any leading X. X: X, etc to allow for multiple instances
         */
        for (const char *p = v->name; *p; p++) {
            if (*p == ':' || *p == ',' || *p == '.') {
                p++;
                if (*p) {
                    type = p;
                }
                break;
            }
        }

        // "+" is used for multi-valued
        if (*type == '+') {
            type++;
            mval = -1;
        }

        if (!X509_NAME_add_entry_by_txt(
                subj,
                type,                           // For example, "C", "ST", "L", "CN", ...
                MBSTRING_UTF8,
                (unsigned char *) v->value,
                -1,                             // len, -1 => NULL terminated
                -1,                             // loc, -1 => append
                mval)) {                        // 0 => not multivalued
            MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, "X509_NAME_add_entry_by_txt",
                "name: %s value: %s", v->name, v->value);
            goto end;
        }
    }

    if (!X509_set_issuer_name(cert, subj)) {
        MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, "X509_set_issuer_name");
        goto end;
    }

    ret = 1;
end:
    return ret;
}

static int _conf_get_extensions(
    const uuid_t correlationId,
    CONF *conf,
    X509 *cert)
{
    const char *title = MSCRYPTP_CREATE_SELF_SIGN_TITLE;
    const char *loc = "";
    int ret = 0;
    const char *extensions = NULL;              // don't free
    X509V3_CTX ctx;

    // Extensions aren't required
    extensions = _conf_get_string(correlationId, conf, "x509_extensions");
    if (extensions == NULL) {
        ret = 1;
        goto end;
    }

    X509V3_set_ctx_test(&ctx);
    X509V3_set_nconf(&ctx, conf);
    if (!X509V3_EXT_add_nconf(conf, &ctx, extensions, NULL)) {
        loc = "test x509_extensions";
        goto openSslErr;
    }

    X509V3_set_ctx(
        &ctx,
        cert,           // issuer
        cert,           // subj
        NULL,           // req
        NULL,           // crl
        0);             // flags
    X509V3_set_nconf(&ctx, conf);
    if (!X509V3_EXT_add_nconf(conf, &ctx, extensions, cert)) {
        loc = "x509_extensions";
        goto openSslErr;
    }

    ret = 1;
end:
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

#define MSCRYPTP_ONE_HOUR_SECONDS   (60 * 60)

static int _conf_get_time(
    const uuid_t correlationId,
    CONF *conf,
    X509 *cert)
{
    const char *title = MSCRYPTP_CREATE_SELF_SIGN_TITLE;
    const char *loc = "";
    int ret = 0;
    long days = 0;

    if (!_conf_get_number(correlationId, conf, "days", &days) || days <= 0) {
        goto end;
    }

    // Set notBefore to one hour before current time
    if (X509_time_adj_ex(X509_getm_notBefore(cert), 0, -MSCRYPTP_ONE_HOUR_SECONDS, NULL) == NULL) {
        loc = "notBefore";
        goto openSslErr;
    }

    // Set notAfter to "days" after current time
    if (X509_time_adj_ex(X509_getm_notAfter(cert), (int) days, 0, NULL) == NULL) {
        loc = "notAfter";
        goto openSslErr;
    }

    ret = 1;
end:
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

static int _conf_sign(
    const uuid_t correlationId,
    CONF *conf,
    X509 *cert,
    EVP_PKEY *pkey)
{
    const char *title = MSCRYPTP_CREATE_SELF_SIGN_TITLE;
    const char *loc = "";
    int ret = 0;
    long days = 0;
    const char *signDigest = NULL;  // don't free
    const char *keyType = NULL;     // don't free
    const EVP_MD *digest = NULL;    // don't free
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;      // don't free
    long rsaPadding = 0;

    signDigest = _conf_get_string(correlationId, conf, "sign_digest");
    if (signDigest == NULL) {
        goto end;
    }

    digest = EVP_get_digestbyname(signDigest);
    if (digest == NULL) {
        loc = "EVP_get_digestbyname";
        MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, loc,
            "sign_digest: %s", signDigest);
        goto end;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        goto openSslErr;
    }

    if (!EVP_DigestSignInit(ctx, &pctx, digest, NULL, pkey)) {
        loc = "EVP_DigestSignInit";
        goto openSslErr;
    }

    keyType = _conf_get_string(correlationId, conf, "key_type");
    if (keyType != NULL && strcmp(keyType, "rsa") == 0) {
        long rsaPadding = 0;

        // Padding values:
        //  # define RSA_PKCS1_PADDING       1
        //  # define RSA_PKCS1_PSS_PADDING   6

        if (!_conf_get_number(correlationId, conf, "rsa_padding", &rsaPadding) || rsaPadding <= 0) {
            goto end;
        }

        if (EVP_PKEY_CTX_set_rsa_padding(pctx, (int) rsaPadding) <= 0) {
            loc = "EVP_PKEY_CTX_set_rsa_padding";
            goto openSslErr;
        }
    }

    if (X509_sign_ctx(cert, ctx) <= 0) {
        loc = "X509_sign_ctx";
        goto openSslErr;
    }

    ret = 1;
end:
    EVP_MD_CTX_free(ctx);       // also frees pctx

    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}


int MSCRYPT_SERVER_create_self_sign_pfx(
    const uuid_t correlationId,
    int mscryptFlags,
    const char *confStr,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // MSCRYPT_free()
    char **outPfxSalt)                  // MSCRYPT_free()
{
    const char *title = MSCRYPTP_CREATE_SELF_SIGN_TITLE;
    const char *loc = "";
    int ret = 0;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    ASN1_INTEGER *serial = NULL;
    int64_t randSerial;
    CONF *conf = NULL;

    *outPfxLength = 0;
    *outPfxBytes = NULL;
    *outPfxSalt = NULL;

    ERR_clear_error();

    cert = X509_new();
    if (cert == NULL) {
        goto openSslErr;
    }

    // V3 version
    if (!X509_set_version(cert, 2)) {
        loc = "X509_set_version";
        goto openSslErr;
    }

    // Random 8 byte serial number
    serial = ASN1_INTEGER_new();
    if (serial == NULL) {
        goto openSslErr;
    }
    RAND_bytes((unsigned char *) &randSerial, sizeof(randSerial));
    if (!ASN1_INTEGER_set_int64(serial, randSerial)) {
        loc = "ASN1_INTEGER_set_int64";
        goto openSslErr;
    }
    if (!X509_set_serialNumber(cert, serial)) {
        loc = "X509_set_serialNumber";
        goto openSslErr;
    }

    if (!_conf_load(correlationId, confStr, &conf)) {
        goto end;
    }

    if (!_conf_get_key(correlationId, conf, cert, &pkey)) {
        goto end;
    }

    if (!_conf_get_name(correlationId, conf, cert)) {
        goto end;
    }

    if (!_conf_get_time(correlationId, conf, cert)) {
        goto end;
    }

    if (!_conf_get_extensions(correlationId, conf, cert)) {
        goto end;
    }

    if (!_conf_sign(correlationId, conf, cert, pkey)) {
        goto end;
    }

    if (!_create_salted_pfx(
            correlationId,
            pkey,
            cert,
            NULL,                       // STACK_OF(X509) *ca
            outPfxLength,
            outPfxBytes,
            outPfxSalt)) {
        goto end;
    }

    ret = 1;

end:
    X509_free(cert);
    EVP_PKEY_free(pkey);
    NCONF_free(conf);
    ASN1_INTEGER_free(serial);
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

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
    char **outSalt)                 // MSCRYPT_free()
{
    int ret = 0;
    void *pkey = NULL;                      // MSCRYPT_SERVER_pfx_free()
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;

    *outPfxLength = 0;
    *outPfxBytes = NULL;
    *outSalt = NULL;

    if (!MSCRYPT_SERVER_pfx_open(
            correlationId,
            inPfxLength,
            inPfxBytes,
            inSalt,
            &pkey)) {
        goto end;
    }

    if (!MSCRYPT_load_pem_cert(
            correlationId,
            pemCertLength,
            pemCertBytes,
            &cert,
            &ca)) {
        goto end;
    }

    if (!_create_salted_pfx(
            correlationId,
            pkey,
            cert,
            ca,
            outPfxLength,
            outPfxBytes,
            outSalt)) {
        goto end;
    }

    ret = 1;

end:
    MSCRYPT_SERVER_pfx_free(pkey);
    X509_free(cert);
    sk_X509_pop_free(ca, X509_free);

    return ret;
}
