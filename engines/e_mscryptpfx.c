/*
 * Copyright 2008-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <mscryptp.h>
#include "e_mscryptpfx_err.h"
#include "e_mscryptpfx_err.c"

static const char *engine_mscryptpfx_id = "mscryptpfx";
static const char *engine_mscryptpfx_name = "MSCrypt PFX ENGINE";

typedef struct MSCRYPTPFX_CTX_st MSCRYPTPFX_CTX;
typedef struct MSCRYPTPFX_KEY_st MSCRYPTPFX_KEY;

static void MSCRYPTPFX_trace(MSCRYPTPFX_CTX *ctx, char *format, ...);

void mscryptpfx_free_key(MSCRYPTPFX_KEY *key);

static EVP_PKEY *mscryptpfx_load_privkey(ENGINE *eng, const char *key_id,
                                         UI_METHOD *ui_method, void *callback_data);

static int mscryptpfx_load_ssl_client_cert(ENGINE *e, SSL *ssl,
                                     STACK_OF(X509_NAME) *ca_dn, X509 **pcert,
                                     EVP_PKEY **pkey, STACK_OF(X509) **pother,
                                     UI_METHOD *ui_method,
                                     void *callback_data);

static int mscryptpfx_rsa_priv_enc(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding);
static int mscryptpfx_rsa_priv_dec(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding);
static int mscryptpfx_rsa_free(RSA *rsa);

static int mscryptpfx_eckey_sign(int type, const unsigned char *dgst, int dlen,
                                 unsigned char *sig, unsigned int *siglen,
                                 const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);

static int mscryptpfx_eckey_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                                       BIGNUM **rp);

static ECDSA_SIG *mscryptpfx_eckey_sign_sig(const unsigned char *dgst, int dgst_len,
                                            const BIGNUM *in_kinv, const BIGNUM *in_r,
                                            EC_KEY *eckey);
static void mscryptpfx_eckey_free(EC_KEY *eckey);


/*
 * This structure contains MSCRYPTPFX ENGINE specific data: it contains various
 * global options and affects how other functions behave.
 */

# define MSCRYPTPFX_DBG_TRACE  2
# define MSCRYPTPFX_DBG_ERROR  1


struct MSCRYPTPFX_CTX_st {
    int debug_level;
    char *debug_file;
};

static MSCRYPTPFX_CTX *mscryptpfx_ctx_new(void);
static void mscryptpfx_ctx_free(MSCRYPTPFX_CTX *ctx);

# define MSCRYPTPFX_CMD_DEBUG_LEVEL            ENGINE_CMD_BASE
# define MSCRYPTPFX_CMD_DEBUG_FILE             (ENGINE_CMD_BASE + 1)
# define MSCRYPTPFX_CMD_EXECUTE_FLAGS          (ENGINE_CMD_BASE + 2)

static const ENGINE_CMD_DEFN mscryptpfx_cmd_defns[] = {
    {MSCRYPTPFX_CMD_DEBUG_LEVEL,
     "debug_level",
     "debug level (1=errors, 2=trace)",
     ENGINE_CMD_FLAG_NUMERIC},

    {MSCRYPTPFX_CMD_DEBUG_FILE,
     "debug_file",
     "debugging filename)",
     ENGINE_CMD_FLAG_STRING},

    {MSCRYPTPFX_CMD_EXECUTE_FLAGS,
     "execute_flags",
     "mscrypt execute flags: 0x1 = inProc, 0x2 = traceLogTest",
     ENGINE_CMD_FLAG_NUMERIC},
    {0, NULL, NULL, 0},
};

static int mscryptpfx_idx = -1;
static int rsa_mscryptpfx_idx = -1;
static int eckey_mscryptpfx_idx = -1;

static int mscryptpfx_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    int ret = 1;
    MSCRYPTPFX_CTX *ctx;
    char *tmpstr;
    if (mscryptpfx_idx == -1) {
        MSCRYPTPFXerr(MSCRYPTPFX_F_CTRL, MSCRYPTPFX_R_ENGINE_NOT_INITIALIZED);
        return 0;
    }
    ctx = ENGINE_get_ex_data(e, mscryptpfx_idx);
    switch (cmd) {

    case MSCRYPTPFX_CMD_DEBUG_LEVEL:
        ctx->debug_level = (int)i;
        MSCRYPTPFX_trace(ctx, "Setting debug level to %d\n", ctx->debug_level);
        break;

    case MSCRYPTPFX_CMD_DEBUG_FILE:
        OPENSSL_free(ctx->debug_file);
        ctx->debug_file = NULL;
        tmpstr = OPENSSL_strdup(p);
        if (tmpstr != NULL) {
            ctx->debug_file = tmpstr;
            MSCRYPTPFX_trace(ctx, "Setting debug file to %s\n", ctx->debug_file);
        } else {
            MSCRYPTPFXerr(MSCRYPTPFX_F_CTRL, MSCRYPTPFX_R_ALLOC_FAILURE);
            ret = 0;
        }
        break;

    case MSCRYPTPFX_CMD_EXECUTE_FLAGS:
        MSCRYPTPFX_trace(ctx, "Setting execute flags to 0x%lx\n", i);
        printf("Setting execute flags to 0x%lx\n", i);
        MSCRYPTP_set_execute_flags((int) i);
        break;

    default:
        MSCRYPTPFXerr(MSCRYPTPFX_F_CTRL, MSCRYPTPFX_R_UNKNOWN_COMMAND);
        ret = 0;
    }

    return ret;
}


static int mscryptpfx_init(ENGINE *e)
{
    MSCRYPTPFX_CTX *ctx;

    if (mscryptpfx_idx < 0) {
#if 0
        if (!MSCRYPT_CLIENT_init())
            goto memerr; 
#endif
        mscryptpfx_idx = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, 0);
        if (mscryptpfx_idx < 0)
            goto memerr;

        /* Setup RSA_METHOD */
        rsa_mscryptpfx_idx = RSA_get_ex_new_index(0, NULL, NULL, NULL, 0);

        /* Setup EC_METHOD */
        eckey_mscryptpfx_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, 0);
    }

    ctx = mscryptpfx_ctx_new();
    if (ctx == NULL)
        goto memerr;

    ENGINE_set_ex_data(e, mscryptpfx_idx, ctx);
    return 1;

 memerr:
    MSCRYPTPFXerr(MSCRYPTPFX_F_INIT, MSCRYPTPFX_R_ALLOC_FAILURE);
    return 0;
}

static int mscryptpfx_destroy(ENGINE *e)
{
    RSA_METHOD *mscryptpfx_rsa_method = (RSA_METHOD *) ENGINE_get_RSA(e);
    EC_KEY_METHOD *mscryptpfx_eckey_method = (EC_KEY_METHOD *) ENGINE_get_EC(e);

    if (mscryptpfx_rsa_method) {
        RSA_meth_free(mscryptpfx_rsa_method);
        ENGINE_set_RSA(e, NULL);
    }
    if (mscryptpfx_eckey_method) {
        EC_KEY_METHOD_free(mscryptpfx_eckey_method);
        ENGINE_set_EC(e, NULL);
    }

    ERR_unload_MSCRYPTPFX_strings();
    return 1;
}

static int mscryptpfx_finish(ENGINE *e)
{
    MSCRYPTPFX_CTX *ctx;
    ctx = ENGINE_get_ex_data(e, mscryptpfx_idx);

#if 0
    MSCRYPT_CLIENT_finish();
#endif

    if (ctx) {
        ENGINE_set_ex_data(e, mscryptpfx_idx, NULL);
        mscryptpfx_ctx_free(ctx);
    }
    return 1;
}

struct MSCRYPTPFX_KEY_st {
    MSCRYPT_PFX_CTX *keyCtx;
    ENGINE *eng;
};


static int bind_mscryptpfx(ENGINE *e)
{
    RSA_METHOD *mscryptpfx_rsa_method = RSA_meth_dup(RSA_PKCS1_OpenSSL());
    EC_KEY_METHOD *mscryptpfx_eckey_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());

    if (!mscryptpfx_rsa_method || !mscryptpfx_eckey_method)
        goto memerr;

    /* Setup RSA_METHOD */
    RSA_meth_set1_name(mscryptpfx_rsa_method, "MSCrypt PFX RSA method");
    if (   !RSA_meth_set_priv_enc(mscryptpfx_rsa_method, mscryptpfx_rsa_priv_enc)
        || !RSA_meth_set_priv_dec(mscryptpfx_rsa_method, mscryptpfx_rsa_priv_dec)
        || !RSA_meth_set_finish(mscryptpfx_rsa_method, mscryptpfx_rsa_free)) {
        goto memerr;
    }

    /* Setup EC_METHOD */
    EC_KEY_METHOD_set_init(mscryptpfx_eckey_method, NULL, mscryptpfx_eckey_free, NULL, NULL, NULL, NULL);
    EC_KEY_METHOD_set_sign(mscryptpfx_eckey_method, mscryptpfx_eckey_sign, mscryptpfx_eckey_sign_setup,
                           mscryptpfx_eckey_sign_sig);

    if (!ENGINE_set_id(e, engine_mscryptpfx_id)
        || !ENGINE_set_name(e, engine_mscryptpfx_name)
        || !ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL)
        || !ENGINE_set_init_function(e, mscryptpfx_init)
        || !ENGINE_set_finish_function(e, mscryptpfx_finish)
        || !ENGINE_set_destroy_function(e, mscryptpfx_destroy)
        || !ENGINE_set_RSA(e, mscryptpfx_rsa_method)
        || !ENGINE_set_EC(e, mscryptpfx_eckey_method)
        || !ENGINE_set_load_privkey_function(e, mscryptpfx_load_privkey)
        || !ENGINE_set_load_ssl_client_cert_function(e,
                                                     mscryptpfx_load_ssl_client_cert)
        || !ENGINE_set_cmd_defns(e, mscryptpfx_cmd_defns)
        || !ENGINE_set_ctrl_function(e, mscryptpfx_ctrl))
        goto memerr;
    ERR_load_MSCRYPTPFX_strings();

    return 1;
 memerr:
    if (mscryptpfx_rsa_method) {
        RSA_meth_free(mscryptpfx_rsa_method);
        ENGINE_set_RSA(e, NULL);
    }
    if (mscryptpfx_eckey_method) {
        EC_KEY_METHOD_free(mscryptpfx_eckey_method);
        ENGINE_set_EC(e, NULL);
    }
    
    return 0;
}

static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_mscryptpfx_id) != 0))
        return 0;
    if (!bind_mscryptpfx(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)

/* MSCrypt PFX load operations */


static int load_pfx_pubkey(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    EVP_PKEY **pkey,
    X509 **cert,            // Optional
    STACK_OF(X509) **ca)    // Optional
{
    const char *title = MSCRYPTP_ENGINE_TITLE;
    int ret = 0;
    X509 *keyCert = NULL;

    *pkey = NULL;
    if (cert) 
        *cert = NULL;

    if (!MSCRYPTP_load_pfx_certs(
            correlationId,
            pfxLength,
            pfxBytes,
            &keyCert,
            ca)) {
        goto end;
    }

    *pkey = X509_get0_pubkey(keyCert);
    if (!*pkey) {
        MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, "X509_get0_pubkey");
        goto end;
    }
    EVP_PKEY_up_ref(*pkey);

    if (cert) {
        *cert = keyCert;
        keyCert = NULL;
    }

    ret = 1;

end:
    X509_free(keyCert);
    return ret;
}


static int mscryptpfx_load(ENGINE *eng, const char *key_id,
                           EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
    const char *title = MSCRYPTP_ENGINE_TITLE;
    const char *loc = "";
    const char *errStr = "Failed";
    int ret = 0;
    MSCRYPTPFX_CTX *ctx = NULL;
    MSCRYPTPFX_KEY *key = NULL;
    uuid_t correlationId;
    int pfxLength = 0;
    unsigned char *pfxBytes = NULL;     // MSCRYPT_free()
    char *salt = NULL;                  // MSCRYPT_clear_free_string()

    *pkey = NULL;
    if (cert)
        *cert = NULL;

    RAND_bytes(correlationId, sizeof(correlationId));

    ERR_clear_error();

    ctx = ENGINE_get_ex_data(eng, mscryptpfx_idx);
    if (!ctx) {
        MSCRYPTPFXerr(MSCRYPTPFX_F_LOAD, MSCRYPTPFX_R_CANT_FIND_MSCRYPTPFX_CONTEXT);
        loc = "ENGINE_get_ex_data";
        goto err;
    }

    key = MSCRYPT_zalloc(sizeof(*key));
    if (!key) {
        MSCRYPTPFXerr(MSCRYPTPFX_F_LOAD, MSCRYPTPFX_R_ALLOC_FAILURE);
        loc = "MSCRYPT_zalloc";
        goto err;
    }

    if (!ENGINE_init(eng)) {
        MSCRYPTPFXerr(MSCRYPTPFX_F_LOAD, MSCRYPTPFX_R_ENGINE_NOT_INITIALIZED);
        loc = "ENGINE_init";
        goto err;
    }

    key->eng = eng;

    if (!MSCRYPT_parse_pfx_engine_key_id(
            correlationId,
            key_id,
            &pfxLength,
            &pfxBytes,
            &salt)) {
        MSCRYPTPFXerr(MSCRYPTPFX_F_LOAD, MSCRYPTPFX_R_PARSE_PFX_KEY_ID_ERROR);
        loc = "MSCRYPT_parse_pfx_engine_key_id";
        goto err;
    }

    if (!load_pfx_pubkey(correlationId, pfxLength, pfxBytes, pkey, cert, ca)) {
        MSCRYPTPFXerr(MSCRYPTPFX_F_LOAD, MSCRYPTPFX_R_LOAD_PFX_PUBKEY_ERROR);
        loc = "load_pfx_pubkey";
        goto err;
    }

    if (EVP_PKEY_id(*pkey) == EVP_PKEY_RSA) {
        loc = "rsa";
        RSA *rsa = EVP_PKEY_get0_RSA(*pkey);        // get0 doesn't up_ref
        const RSA_METHOD *mscryptpfx_rsa_method = ENGINE_get_RSA(eng);
        if (!rsa || !mscryptpfx_rsa_method) {
            MSCRYPTPFXerr(MSCRYPTPFX_F_LOAD, MSCRYPTPFX_R_INVALID_RSA);
            goto err;
        }

        if (!MSCRYPT_CLIENT_pfx_open(correlationId, pfxLength, pfxBytes, salt, &key->keyCtx)) {
            MSCRYPTPFXerr(MSCRYPTPFX_F_LOAD, MSCRYPTPFX_R_PFX_OPEN_ERROR);
            goto err;
        }
        RSA_set_method(rsa, mscryptpfx_rsa_method);
        RSA_set_ex_data(rsa, rsa_mscryptpfx_idx, key);
    } else if (EVP_PKEY_id(*pkey) == EVP_PKEY_EC) {
        loc = "ec";
        EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(*pkey);   // get0 doesn't up_ref
        const EC_KEY_METHOD *mscryptpfx_eckey_method = ENGINE_get_EC(eng);
        if (!eckey || !mscryptpfx_eckey_method) {
            MSCRYPTPFXerr(MSCRYPTPFX_F_LOAD, MSCRYPTPFX_R_INVALID_EC_KEY);
            goto err;
        }

        if (!MSCRYPT_CLIENT_pfx_open(correlationId, pfxLength, pfxBytes, salt, &key->keyCtx)) {
            MSCRYPTPFXerr(MSCRYPTPFX_F_LOAD, MSCRYPTPFX_R_PFX_OPEN_ERROR);
            goto err;
        }

        EC_KEY_set_method(eckey, mscryptpfx_eckey_method);
        EC_KEY_set_ex_data(eckey, eckey_mscryptpfx_idx, key);
    } else {
        loc = "unsupported";
        MSCRYPTPFXerr(MSCRYPTPFX_F_LOAD, MSCRYPTPFX_R_UNSUPPORTED_KEY_ALGORITHM);
        goto err;
    }

    ret = 1;

end:
    MSCRYPT_free(pfxBytes);
    MSCRYPT_clear_free_string(salt);
    return ret;

err:
    MSCRYPTP_trace_log_error(correlationId, 0, title, loc, errStr);

    mscryptpfx_free_key(key);
    if (*pkey) {
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }
    if (cert && *cert) {
        X509_free(*cert);
        *cert = NULL;
    }

    goto end;
}


static EVP_PKEY *mscryptpfx_load_privkey(ENGINE *eng, const char *key_id,
                                         UI_METHOD *ui_method, void *callback_data)
{
    EVP_PKEY *pkey = NULL;

    mscryptpfx_load(eng, key_id, &pkey, NULL, NULL);
    return pkey;
}

static int mscryptpfx_load_ssl_client_cert(ENGINE *e, SSL *ssl,
                                           STACK_OF(X509_NAME) *ca_dn, X509 **pcert,
                                           EVP_PKEY **pkey, STACK_OF(X509) **pother,
                                           UI_METHOD *ui_method,
                                           void *callback_data)
{
    // Need key_id
    MSCRYPTPFXerr(MSCRYPTPFX_F_LOAD, MSCRYPTPFX_R_UNSUPPORTED_SSL_CLIENT_CERT);
    MSCRYPTP_trace_log_error(NULL, 0, MSCRYPTP_ENGINE_TITLE, NULL, "Not supported");
    return 0;

#if 0
    return mscryptpfx_load(e, NULL, pkey, pcert, pother);
#endif
}

/* MSCrypt PFX RSA operations */


static int get_rsa_key_ctx(RSA *rsa,
                           MSCRYPT_PFX_CTX **keyCtx)
{
    MSCRYPTPFX_KEY *mscryptpfx_key;

    *keyCtx = 0;

    mscryptpfx_key = RSA_get_ex_data(rsa, rsa_mscryptpfx_idx);
    if (!mscryptpfx_key || !mscryptpfx_key->keyCtx) {
//        MSCRYPTPFXerr(MSCRYPTPFX_F_GET_PRIVATE_RSA, MSCRYPTPFX_R_CANT_GET_KEY);
        return 0;
    }

    *keyCtx = mscryptpfx_key->keyCtx;

    return 1;
}

typedef int (*PFN_RSA_meth_priv_enc)(
    int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding);

static int mscryptpfx_rsa_priv_enc(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding)
{
    MSCRYPT_PFX_CTX *keyCtx = NULL;

    if (get_rsa_key_ctx(rsa, &keyCtx)) {
        return MSCRYPT_CLIENT_rsa_private_encrypt(
            keyCtx,
            flen,
            from,
	        RSA_size(rsa),
            to,
            padding);
    } else {
        const RSA_METHOD *ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        PFN_RSA_meth_priv_enc pfn_rsa_meth_priv_enc = RSA_meth_get_priv_enc(ossl_rsa_meth);
        if (!pfn_rsa_meth_priv_enc) {
            MSCRYPTPFXerr(MSCRYPTPFX_F_RSA_PRIV_ENC, MSCRYPTPFX_R_CANT_GET_METHOD);
            return -1;
        }

        return pfn_rsa_meth_priv_enc(flen, from, to, rsa, padding);
    }
}

typedef int (*PFN_RSA_meth_priv_dec)(
    int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding);

static int mscryptpfx_rsa_priv_dec(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding)
{
    MSCRYPT_PFX_CTX *keyCtx = NULL;

    if (get_rsa_key_ctx(rsa, &keyCtx)) {
        return MSCRYPT_CLIENT_rsa_private_decrypt(
            keyCtx,
            flen,
            from,
	        RSA_size(rsa),
            to,
            padding);
    } else {
        const RSA_METHOD *ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        PFN_RSA_meth_priv_dec pfn_rsa_meth_priv_dec = RSA_meth_get_priv_dec(ossl_rsa_meth);

        if (!pfn_rsa_meth_priv_dec) {
            MSCRYPTPFXerr(MSCRYPTPFX_F_RSA_PRIV_DEC, MSCRYPTPFX_R_CANT_GET_METHOD);
            return -1;
        }

        return pfn_rsa_meth_priv_dec(flen, from, to, rsa, padding);
    }
}

static int mscryptpfx_rsa_free(RSA *rsa)
{
    MSCRYPTPFX_KEY *mscryptpfx_key;
    mscryptpfx_key = RSA_get_ex_data(rsa, rsa_mscryptpfx_idx);
    mscryptpfx_free_key(mscryptpfx_key);
    RSA_set_ex_data(rsa, rsa_mscryptpfx_idx, NULL);
    return 1;
}

/* MSCrypt PFX EC operations */

static int get_ec_key_ctx(EC_KEY *eckey,
                          MSCRYPT_PFX_CTX **keyCtx)
{
    MSCRYPTPFX_KEY *mscryptpfx_key;

    *keyCtx = NULL;

    mscryptpfx_key = EC_KEY_get_ex_data(eckey, eckey_mscryptpfx_idx);
    if (!mscryptpfx_key || !mscryptpfx_key->keyCtx) {
//        MSCRYPTPFXerr(MSCRYPTPFX_F_GET_PRIVATE_EC_KEY, MSCRYPTPFX_R_CANT_GET_KEY);
        return 0;
    }

    *keyCtx = mscryptpfx_key->keyCtx;

    return 1;
}

typedef int (*PFN_eckey_sign)(
    int type, const unsigned char *dgst, int dlen,
    unsigned char *sig, unsigned int *siglen,
    const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);

static int mscryptpfx_eckey_sign(int type, const unsigned char *dgst, int dlen,
                                 unsigned char *sig, unsigned int *siglen,
                                 const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
    MSCRYPT_PFX_CTX *keyCtx = NULL;

    if (get_ec_key_ctx(eckey, &keyCtx)) {
	    *siglen = 0;
        return MSCRYPT_CLIENT_ecdsa_sign(
            keyCtx,
            type,
            dgst,
            dlen,
            sig,
            (unsigned int) ECDSA_size(eckey),
            siglen);
    } else {
        const EC_KEY_METHOD *ossl_eckey_method = EC_KEY_OpenSSL();
        PFN_eckey_sign pfn_eckey_sign = NULL;

        EC_KEY_METHOD_get_sign(ossl_eckey_method, &pfn_eckey_sign, NULL, NULL);
        if (!pfn_eckey_sign) {
            MSCRYPTPFXerr(MSCRYPTPFX_F_EC_KEY_SIGN, MSCRYPTPFX_R_CANT_GET_METHOD);
            return 0;
        }

        return pfn_eckey_sign(type, dgst, dlen, sig, siglen, kinv, r, eckey);
    }
}

typedef int (*PFN_eckey_sign_setup)(
    EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
    BIGNUM **rp);

static int mscryptpfx_eckey_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                                     BIGNUM **rp)
{
    const EC_KEY_METHOD *ossl_eckey_method = EC_KEY_OpenSSL();
    PFN_eckey_sign_setup pfn_eckey_sign_setup = NULL;

    EC_KEY_METHOD_get_sign(ossl_eckey_method, NULL, &pfn_eckey_sign_setup, NULL);
    if (!pfn_eckey_sign_setup) {
        MSCRYPTPFXerr(MSCRYPTPFX_F_EC_KEY_SIGN_SETUP, MSCRYPTPFX_R_CANT_GET_METHOD);
        return 0;
    }

    return pfn_eckey_sign_setup(eckey, ctx_in, kinvp, rp);
}

typedef ECDSA_SIG *(*PFN_eckey_sign_sig)(
    const unsigned char *dgst, int dgst_len,
    const BIGNUM *in_kinv, const BIGNUM *in_r,
    EC_KEY *eckey);

static ECDSA_SIG *mscryptpfx_eckey_sign_sig(const unsigned char *dgst, int dgst_len,
                                            const BIGNUM *in_kinv, const BIGNUM *in_r,
                                            EC_KEY *eckey)
{
    MSCRYPT_PFX_CTX *keyCtx = NULL;

    if (get_ec_key_ctx(eckey, &keyCtx)) {
        unsigned char *sig = NULL;
        unsigned int siglen = (unsigned int) ECDSA_size(eckey);
        ECDSA_SIG *decodedSig = NULL;

        if (siglen > 0) {
            sig = (unsigned char *) MSCRYPT_zalloc(siglen);
        }
        if (sig == NULL) {
            MSCRYPTPFXerr(MSCRYPTPFX_F_CTX_NEW, MSCRYPTPFX_R_ALLOC_FAILURE);
            return NULL;
        }

        if (MSCRYPT_CLIENT_ecdsa_sign(
                keyCtx,
                0,              // type
                dgst,
                dgst_len,
                sig,
                siglen,
                &siglen)) {
            const unsigned char *p = sig;
            decodedSig = d2i_ECDSA_SIG(NULL, &p, (long) siglen);
        }

        MSCRYPT_free(sig);
        if (!decodedSig)
            MSCRYPTPFXerr(MSCRYPTPFX_F_EC_KEY_SIGN_SETUP, MSCRYPTPFX_R_CANT_GET_METHOD);
        return decodedSig;
    } else {
        const EC_KEY_METHOD *ossl_eckey_method = EC_KEY_OpenSSL();
        PFN_eckey_sign_sig pfn_eckey_sign_sig = NULL;

        EC_KEY_METHOD_get_sign(ossl_eckey_method, NULL, NULL, &pfn_eckey_sign_sig);
        if (!pfn_eckey_sign_sig) {
            MSCRYPTPFXerr(MSCRYPTPFX_F_EC_KEY_SIGN_SIG, MSCRYPTPFX_R_CANT_GET_METHOD);
            return NULL;
        }

        return pfn_eckey_sign_sig(dgst, dgst_len, in_kinv, in_r, eckey);
    }
}

static void mscryptpfx_eckey_free(EC_KEY *eckey)
{
    MSCRYPTPFX_KEY *mscryptpfx_key;
    mscryptpfx_key = EC_KEY_get_ex_data(eckey, eckey_mscryptpfx_idx);
    mscryptpfx_free_key(mscryptpfx_key);
    EC_KEY_set_ex_data(eckey, eckey_mscryptpfx_idx, NULL);
}


static void mscryptpfx_vtrace(MSCRYPTPFX_CTX *ctx, int level, char *format,
                        va_list argptr)
{
    BIO *out;

    if (!ctx || (ctx->debug_level < level) || (!ctx->debug_file))
        return;
    out = BIO_new_file(ctx->debug_file, "a+");
    if (out == NULL) {
        MSCRYPTPFXerr(MSCRYPTPFX_F_VTRACE, MSCRYPTPFX_R_FILE_OPEN_ERROR);
        return;
    }
    BIO_vprintf(out, format, argptr);
    BIO_free(out);
}

static void MSCRYPTPFX_trace(MSCRYPTPFX_CTX *ctx, char *format, ...)
{
    va_list args;
    va_start(args, format);
    mscryptpfx_vtrace(ctx, MSCRYPTPFX_DBG_TRACE, format, args);
    va_end(args);
}

void mscryptpfx_free_key(MSCRYPTPFX_KEY *key)
{
    if (!key)
        return;
    if (key->keyCtx)
        MSCRYPT_CLIENT_pfx_close(key->keyCtx);
    if (key->eng)
        ENGINE_finish(key->eng);
    MSCRYPT_free(key);
}

/* Initialize a MSCRYPTPFX_CTX structure */

static MSCRYPTPFX_CTX *mscryptpfx_ctx_new(void)
{
    MSCRYPTPFX_CTX *ctx = MSCRYPT_zalloc(sizeof(*ctx));

    if (ctx == NULL) {
        MSCRYPTPFXerr(MSCRYPTPFX_F_CTX_NEW, MSCRYPTPFX_R_ALLOC_FAILURE);
        return NULL;
    }
    return ctx;
}

static void mscryptpfx_ctx_free(MSCRYPTPFX_CTX *ctx)
{
    MSCRYPTPFX_trace(ctx, "Calling mscryptpfx_ctx_free with %lx\n", ctx);
    if (!ctx)
        return;
    OPENSSL_free(ctx->debug_file);
    MSCRYPT_free(ctx);
}


// To link windows

static ENGINE *engine_mscryptpfx(void)
{
    ENGINE *e = ENGINE_new();
    if (e == NULL) {
        return NULL;
    }

    if (!bind_mscryptpfx(e)) {
        ENGINE_free(e);
        return NULL;
    }
    return e;
}

int  MSCRYPTPFX_install_engine(
    const uuid_t correlationId)
{
    const char *title = MSCRYPTP_ENGINE_TITLE;
    const char *loc = "";
    int ret = 0;
    ENGINE *e = NULL;

//    MSCRYPTP_trace_log(correlationId, MSCRYPTP_TRACELOG_VERBOSE_FLAG, title, "Start");
    MSCRYPTP_trace_log(correlationId, 0, title, "Start");

    ERR_clear_error();

    e = engine_mscryptpfx();
    if (e == NULL) {
        loc = "create";
        goto openSslErr;
    }

    if (!ENGINE_add(e)) {
        loc = "add";
        goto openSslErr;
    }

    ret = 1;

end:
    if (e != NULL) {
        ENGINE_free(e);
    }

    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}
