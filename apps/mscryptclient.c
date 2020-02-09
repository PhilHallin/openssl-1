// #define MSCRYPT_NO_GDBUS_RPC 1
#ifdef MSCRYPT_TEST_WINDOWS
#define MSCRYPT_NO_GDBUS_RPC 1
#endif

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
#include "mscryptp.h"
#ifndef MSCRYPT_NO_GDBUS_RPC
#include "mscryptgdbusclient.h"
#endif


#ifndef MSCRYPT_NO_GDBUS_RPC
int MSCRYPTP_inProc = 0;
#else
int MSCRYPTP_inProc = 1;
#endif

//
// Shared Memory Functions called from the client
//

MSCRYPT_SHARED_MEM *MSCRYPT_open_shared_mem(
    const uuid_t correlationId,
    int memLength,
    unsigned char **memBytes)
{
    int ret = 0;
    MSCRYPT_SHARED_MEM *sharedMem = NULL;
    uuid_t randId;

    *memBytes = NULL;

    if (correlationId == NULL) {
        RAND_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    sharedMem = (MSCRYPT_SHARED_MEM *) MSCRYPT_zalloc(sizeof(MSCRYPT_SHARED_MEM));
    if (sharedMem == NULL) {
        goto end;
    }

    memcpy(sharedMem->correlationId, correlationId, sizeof(sharedMem->correlationId));
    sharedMem->memLength = memLength;

    if (MSCRYPTP_inProc) {
        sharedMem->memBytes = (unsigned char *) MSCRYPT_zalloc(memLength);
        if (sharedMem->memBytes == NULL) {
            goto end;
        }
        ret = 1;
    } else {
#ifndef MSCRYPT_NO_GDBUS_RPC
        ret = MSCRYPT_GDBUS_open_shared_mem(sharedMem);
#endif
    }

    *memBytes = sharedMem->memBytes;

end:
    if (!ret) {
        MSCRYPT_close_shared_mem(sharedMem);
        sharedMem = NULL;
    }

    return sharedMem;
}

void MSCRYPT_close_shared_mem(
    MSCRYPT_SHARED_MEM *sharedMem)
{
    if (sharedMem == NULL) {
        return;
    }

    if (MSCRYPTP_inProc) {
        MSCRYPT_free(sharedMem->memBytes);
    } else {
#ifndef MSCRYPT_NO_GDBUS_RPC
        MSCRYPT_GDBUS_close_shared_mem(sharedMem);
#endif
    }

    MSCRYPT_free(sharedMem);
}


const char *MSCRYPTP_get_cert_ctrl_title(
    int ctrl,
    int location)
{
    const char *title = "???";
    switch (ctrl) {
        case MSCRYPT_CERT_CTRL_IMPORT:
            if (location == MSCRYPT_CERT_LOCATION_ROOT) {
                title = MSCRYPTP_IMPORT_TRUSTED_TITLE;
            } else if (location == MSCRYPT_CERT_LOCATION_DISALLOWED) {
                title = MSCRYPTP_IMPORT_DISALLOWED_TITLE;
            }
            break;
        case MSCRYPT_CERT_CTRL_REMOVE:
            if (location == MSCRYPT_CERT_LOCATION_ROOT) {
                title = MSCRYPTP_REMOVE_TRUSTED_TITLE;
            } else if (location == MSCRYPT_CERT_LOCATION_DISALLOWED) {
                title = MSCRYPTP_REMOVE_DISALLOWED_TITLE;
            }
            break;
        case MSCRYPT_CERT_CTRL_ENUM:
            if (location == MSCRYPT_CERT_LOCATION_ROOT) {
                title = MSCRYPTP_ENUM_TRUSTED_TITLE;
            } else if (location == MSCRYPT_CERT_LOCATION_DISALLOWED) {
                title = MSCRYPTP_ENUM_DISALLOWED_TITLE;
            }
            break;
        case MSCRYPT_CERT_CTRL_FIND:
            if (location == MSCRYPT_CERT_LOCATION_ROOT) {
                title = MSCRYPTP_IS_TRUSTED_TITLE;
            } else if (location == MSCRYPT_CERT_LOCATION_DISALLOWED) {
                title = MSCRYPTP_IS_DISALLOWED_TITLE;
            }
            break;
    }

    return title;
}

const char *MSCRYPTP_get_ctl_ctrl_title(
    int ctrl,
    int location)
{
    const char *title = "???";
    if (location == MSCRYPT_CERT_LOCATION_DISALLOWED) {
        switch (ctrl) {
            case MSCRYPT_CERT_CTRL_IMPORT:
                title = MSCRYPTP_IMPORT_DISALLOWED_CTL_TITLE;
                break;
            case MSCRYPT_CERT_CTRL_REMOVE:
                title = MSCRYPTP_REMOVE_DISALLOWED_CTL_TITLE;
                break;
        }
    }

    return title;
}


int MSCRYPT_CLIENT_cert_ctrl(
    const uuid_t correlationId,
    MSCRYPT_SHARED_MEM *sharedMem,
    int ctrl,
    int location,
    int format,
    int length,
    const unsigned char *bytes)
{
    const char *title = MSCRYPTP_get_cert_ctrl_title(ctrl, location);
    int ret = 0;
    uuid_t randId;
    const char *formatStr = "";

    if (correlationId == NULL) {
        RAND_bytes(randId, sizeof(randId));
        correlationId = randId;
    }


    switch (format) {
        case MSCRYPT_CERT_FORMAT_DER:
            formatStr = "der";
            break;
        case MSCRYPT_CERT_FORMAT_PEM:
            formatStr = "pem";
            break;
        case MSCRYPT_CERT_FORMAT_SST:
            formatStr = "sst";
            break;
        case MSCRYPT_CERT_FORMAT_CTL:
            formatStr = "ctl";
            title = MSCRYPTP_get_ctl_ctrl_title(ctrl, location);
            break;
        default:
            formatStr = "???";
    }

    MSCRYPTP_trace_log_para(correlationId, 0, title, "Start",
        "format: %s length: %d",
        formatStr, length);

    ERR_clear_error();

    if (MSCRYPTP_inProc) {
        ret = MSCRYPT_SERVER_cert_ctrl(
            correlationId,
            ctrl,
            location,
            format,
            length,
            bytes);
    } else {
#ifndef MSCRYPT_NO_GDBUS_RPC
        ret = MSCRYPT_GDBUS_CLIENT_cert_ctrl(
            correlationId,
            sharedMem,
            ctrl,
            location,
            format,
            length,
            bytes);
#endif
    }

    if (ret > 0) {
        MSCRYPTP_trace_log(correlationId, 0, title, "Complete");
    } else {
        MSCRYPTP_trace_log_error(correlationId, 0, title, "Complete",
            ret < 0 ? "Partial updates" : "No updates");
    }

    return ret;
}

int MSCRYPT_CLIENT_import_pfx(
    const uuid_t correlationId,
    int mscryptFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inPassword,             // Optional
    int *outVerifyChainError,
    int *outPfxLength,
    unsigned char **outPfxBytes,         // MSCRYPT_free()
    char **outPfxSalt)                   // MSCRYPT_free()
{
    const char *title = MSCRYPTP_IMPORT_PFX_TITLE;
    int ret = 0;
    uuid_t randId;

    if (correlationId == NULL) {
        RAND_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    MSCRYPTP_trace_log_para(correlationId, 0, title, "Start",
        "flags: 0x%x length: %d",
        mscryptFlags, inPfxLength);

    ERR_clear_error();

    if (MSCRYPTP_inProc) {
        ret = MSCRYPT_SERVER_import_pfx(
            correlationId,
            mscryptFlags,
            inPfxLength,
            inPfxBytes,
            inPassword,             // Optional
            outVerifyChainError,
            outPfxLength,
            outPfxBytes,            // MSCRYPT_free()
            outPfxSalt);            // MSCRYPT_free()
    } else {
#ifndef MSCRYPT_NO_GDBUS_RPC
        ret = MSCRYPT_GDBUS_CLIENT_import_pfx(
            correlationId,
            mscryptFlags,
            inPfxLength,
            inPfxBytes,
            inPassword,             // Optional
            outVerifyChainError,
            outPfxLength,
            outPfxBytes,            // MSCRYPT_free()
            outPfxSalt);            // MSCRYPT_free()
#endif
    }

    if (ret > 0) {
        MSCRYPTP_trace_log(correlationId, 0, title, "Complete");
    } else {
        if (ret < 0) {
            MSCRYPTP_trace_log_openssl_verify_cert_error(correlationId, 0, title,
                "X509_verify_cert", *outVerifyChainError);
        }
        MSCRYPTP_trace_log_error(correlationId, 0, title, "Complete",
            ret < 0 ? "Import succeeded with certificate errors" : "Import failed");
    }

    return ret;
}

// Returns 1 for success and 0 for an error
int MSCRYPT_create_self_sign_pfx(
    const uuid_t correlationId,
    int mscryptFlags,
    const char *confStr,
    int *pfxLength,
    unsigned char **pfxBytes,        // MSCRYPT_free()
    char **pfxSalt)                  // MSCRYPT_free()
{
    const char *title = MSCRYPTP_CREATE_SELF_SIGN_TITLE;
    int ret = 0;
    uuid_t randId;
    BIO *fileBio = NULL;

    if (correlationId == NULL) {
        RAND_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    MSCRYPTP_trace_log_para(correlationId, 0, title, "Start",
        "flags: 0x%x", mscryptFlags);

    ERR_clear_error();

    if (strncmp(confStr, "file:", 5) == 0) {
        char *fileString = NULL;        // don't free
        fileBio = MSCRYPTP_read_file_string(correlationId, confStr + 5, 0,  &fileString);
        if (fileBio == NULL) {
            goto end;
        }
        confStr = fileString;
    }

    if (MSCRYPTP_inProc) {
        ret = MSCRYPT_SERVER_create_self_sign_pfx(
            correlationId,
            mscryptFlags,
            confStr,
            pfxLength,
            pfxBytes,            // MSCRYPT_free()
            pfxSalt);            // MSCRYPT_free()
    } else {
#ifndef MSCRYPT_NO_GDBUS_RPC
        ret = MSCRYPT_GDBUS_CLIENT_create_self_sign_pfx(
            correlationId,
            mscryptFlags,
            confStr,
            pfxLength,
            pfxBytes,            // MSCRYPT_free()
            pfxSalt);            // MSCRYPT_free()
#endif
    }

end:
    if (ret) {
        MSCRYPTP_trace_log(correlationId, 0, title, "Complete");
    } else {
        MSCRYPTP_trace_log_error(correlationId, 0, title, "Complete",
            "Create failed");
    }

    BIO_free(fileBio);
    return ret;
}

// Returns 1 for success and 0 for an error
int MSCRYPT_create_self_sign_pfx_to_key_id(
    const uuid_t correlationId,
    int mscryptFlags,
    const char *confStr,
    char **keyId)                     // MSCRYPT_free()
{
    int ret = 0;
    int pfxLength = 0;
    unsigned char *pfxBytes = NULL;     // MSCRYPT_free()
    char *salt = NULL;                  // MSCRYPT_clear_free_string()

    *keyId = NULL;

    if (!MSCRYPT_create_self_sign_pfx(
            correlationId,
            mscryptFlags,
            confStr,
            &pfxLength,
            &pfxBytes,
            &salt)) {
        goto end;
    }

    if (!MSCRYPT_format_pfx_engine_key_id(
            correlationId,
            pfxLength,
            pfxBytes,
            salt,
            keyId)) {
        goto end;
    }

    ret = 1;

end:
    MSCRYPT_free(pfxBytes);
    MSCRYPT_clear_free_string(salt);

    return ret;
}


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
    unsigned char **outPfxBytes,    // MSCRYPT_free()
    char **outSalt)                 // MSCRYPT_free()
{
    const char *title = MSCRYPTP_HELPER_PFX_TITLE;
    int ret = 0;
    uuid_t randId;

    *outPfxLength = 0;
    *outPfxBytes = NULL;
    *outSalt = NULL;

    if (correlationId == NULL) {
        RAND_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    MSCRYPTP_trace_log_para(correlationId, 0, title, "Start",
        "flags: 0x%x", mscryptFlags);

    ERR_clear_error();


    if (MSCRYPTP_inProc) {
        ret = MSCRYPT_SERVER_replace_pfx_certs(
            correlationId,
            mscryptFlags,
            inPfxLength,
            inPfxBytes,
            inSalt,
            pemCertLength,
            pemCertBytes,
            outPfxLength,
            outPfxBytes,                // MSCRYPT_free()
            outSalt);                   // MSCRYPT_free()
    } else {
#ifndef MSCRYPT_NO_GDBUS_RPC
        ret = MSCRYPT_GDBUS_CLIENT_replace_pfx_certs(
            correlationId,
            mscryptFlags,
            inPfxLength,
            inPfxBytes,
            inSalt,
            pemCertLength,
            pemCertBytes,
            outPfxLength,
            outPfxBytes,                // MSCRYPT_free()
            outSalt);                   // MSCRYPT_free()
#endif
    }

    if (ret) {
        MSCRYPTP_trace_log(correlationId, 0, title, "Complete");
    } else {
        MSCRYPTP_trace_log_error(correlationId, 0, title, "Complete",
            "Replace certificates in PFX failed");
    }

    return ret;
}

int MSCRYPT_replace_key_id_certs(
    const uuid_t correlationId,
    int mscryptFlags,
    const char *inKeyId,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    char **outKeyId)                     // MSCRYPT_free()
{
    int ret = 0;
    int inPfxLength = 0;
    unsigned char *inPfxBytes = NULL;   // MSCRYPT_free()
    char *inSalt = NULL;                // MSCRYPT_clear_free_string()
    int outPfxLength = 0;
    unsigned char *outPfxBytes = NULL;  // MSCRYPT_free()
    char *outSalt = NULL;               // MSCRYPT_clear_free_string()

    *outKeyId = NULL;

    if (!MSCRYPT_parse_pfx_engine_key_id(
            correlationId,
            inKeyId,
            &inPfxLength,
            &inPfxBytes,
            &inSalt)) {
        goto end;
    }

    if (!MSCRYPT_replace_pfx_certs(
            correlationId,
            mscryptFlags,
            inPfxLength,
            inPfxBytes,
            inSalt,
            pemCertLength,
            pemCertBytes,
            &outPfxLength,
            &outPfxBytes,
            &outSalt)) {
        goto end;
    }

    if (!MSCRYPT_format_pfx_engine_key_id(
            correlationId,
            outPfxLength,
            outPfxBytes,
            outSalt,
            outKeyId)) {
        goto end;
    }

    ret = 1;

end:
    MSCRYPT_free(inPfxBytes);
    MSCRYPT_clear_free_string(inSalt);
    MSCRYPT_free(outPfxBytes);
    MSCRYPT_clear_free_string(outSalt);

    return ret;
}

int MSCRYPT_replace_key_id_certs2(
    const uuid_t correlationId,
    int mscryptFlags,
    const char *inKeyId,
    X509 *cert,
    STACK_OF(X509) *ca,                 // Optional
    char **outKeyId)                    // MSCRYPT_free()
{
    int ret = 0;
    int pemCertLength = 0;
    char *pemCert = NULL;    // MSCRYPT_free()

    *outKeyId = NULL;

    if (!MSCRYPTP_pem_from_certs(
            correlationId,
            cert,
            ca,
            &pemCertLength,
            &pemCert)) {
        goto end;
    }

    if (!MSCRYPT_replace_key_id_certs(
            correlationId,
            mscryptFlags,
            inKeyId,
            pemCertLength,
            (unsigned char *) pemCert,
            outKeyId)) {                  // MSCRYPT_free()
        goto end;
    }

    ret = 1;

end:
    MSCRYPT_free(pemCert);
    return ret;
}


int MSCRYPT_CLIENT_pfx_open(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    const char *salt,
    MSCRYPT_PFX_CTX **keyCtx)
{
    const char *title = MSCRYPTP_OPEN_PFX_TITLE;
    int ret = 0;
    MSCRYPT_PFX_CTX *ctx = NULL;

    ERR_clear_error();

    ctx = (MSCRYPT_PFX_CTX *) MSCRYPT_zalloc(sizeof(MSCRYPT_PFX_CTX));
    if (ctx == NULL) {
        goto end;
    }

    if (correlationId == NULL) {
        RAND_bytes(ctx->correlationId, sizeof(ctx->correlationId));
    } else {
        memcpy(ctx->correlationId, correlationId, sizeof(ctx->correlationId));
    }

    MSCRYPTP_trace_log(ctx->correlationId, 0, title, "Start");

    if (MSCRYPTP_inProc) {
        ret = MSCRYPT_SERVER_pfx_open(
            ctx->correlationId,
            pfxLength,
            pfxBytes,
            salt,
            &ctx->pkey);
    } else {
#ifndef MSCRYPT_NO_GDBUS_RPC
        ret = MSCRYPT_GDBUS_CLIENT_pfx_open(
            ctx,
            pfxLength,
            pfxBytes,
            salt);
#endif
    }

end:
    if (!ret) {
        MSCRYPTP_trace_log_error(ctx->correlationId, 0, title, "Complete", "Open failed");
        MSCRYPT_CLIENT_pfx_close(ctx);
        ctx = NULL;
    } else {
        MSCRYPTP_trace_log(ctx->correlationId, 0, title, "Complete");
    }

    *keyCtx = ctx;
    return ret;
}

void MSCRYPT_CLIENT_pfx_close(
    MSCRYPT_PFX_CTX *keyCtx)
{
    const char *title = MSCRYPTP_CLOSE_PFX_TITLE;
    if (keyCtx == NULL) {
        return;
    }

    MSCRYPTP_trace_log(keyCtx->correlationId, 0, title, "Start");

    if (MSCRYPTP_inProc) {
        MSCRYPT_SERVER_pfx_free(keyCtx->pkey);
    } else {
#ifndef MSCRYPT_NO_GDBUS_RPC
        MSCRYPT_GDBUS_CLIENT_pfx_close(keyCtx);
#endif
    }

    MSCRYPTP_trace_log(keyCtx->correlationId, 0, title, "Complete");

    MSCRYPT_free(keyCtx);
}

int MSCRYPT_CLIENT_rsa_private_encrypt(
    MSCRYPT_PFX_CTX *keyCtx,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding)
{
    int ret = -1;

    ERR_clear_error();
    if (MSCRYPTP_inProc) {
        ret = MSCRYPT_SERVER_rsa_private_encrypt(
            keyCtx->correlationId,
            keyCtx->pkey,
            flen,
            from,
            tlen,
            to,
            padding);
    } else {
#ifndef MSCRYPT_NO_GDBUS_RPC
        ret = MSCRYPT_GDBUS_CLIENT_rsa_private_encrypt_decrypt(
            keyCtx,
            0,                  // decrypt
            flen,
            from,
            tlen,
            to,
            padding);
#endif
    }

    return ret;
}

int MSCRYPT_CLIENT_rsa_private_decrypt(
    MSCRYPT_PFX_CTX *keyCtx,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding)
{
    int ret = -1;

    ERR_clear_error();
    if (MSCRYPTP_inProc) {
        ret = MSCRYPT_SERVER_rsa_private_decrypt(
            keyCtx->correlationId,
            keyCtx->pkey,
            flen,
            from,
            tlen,
            to,
            padding);
    } else {
#ifndef MSCRYPT_NO_GDBUS_RPC
        ret = MSCRYPT_GDBUS_CLIENT_rsa_private_encrypt_decrypt(
            keyCtx,
            1,                  // decrypt
            flen,
            from,
            tlen,
            to,
            padding);
#endif
    }

    return ret;
}

int MSCRYPT_CLIENT_ecdsa_sign(
    MSCRYPT_PFX_CTX *keyCtx,
    int type,
    const unsigned char *dgst,
    int dlen,
    unsigned char *sig,
    unsigned int siglen,
    unsigned int *outlen)
{
    int ret = -1;

    ERR_clear_error();
    if (MSCRYPTP_inProc) {
        ret = MSCRYPT_SERVER_ecdsa_sign(
            keyCtx->correlationId,
            keyCtx->pkey,
            type,
            dgst,
            dlen,
            sig,
            siglen,
            outlen);
    } else {
#ifndef MSCRYPT_NO_GDBUS_RPC
        ret = MSCRYPT_GDBUS_CLIENT_ecdsa_sign(
            keyCtx,
            type,
            dgst,
            dlen,
            sig,
            siglen,
            outlen);
#endif
    }

    return ret;
}
