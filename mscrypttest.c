// #define MSCRYPT_TEST_WINDOWS 1

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/engine.h>
#include "mscryptctl.h"
#include "mscryptp.h"
#include "mscryptctl.h"

#ifdef MSCRYPT_TEST_WINDOWS
#define strcasecmp _stricmp

#include <windows.h>

static
void
_my_sleep(
    int milliseconds)
{
    Sleep((DWORD) milliseconds);
}

#else

#include <glib.h>

static
void
_my_sleep(
    int milliseconds)
{
    g_usleep((gulong)(milliseconds * 1000));    // units of microseconds
}

#endif

#define ARRAY_SIZE(foo) (sizeof(foo)/sizeof(foo[0]))

static void Usage(void)
{
    printf("Usage:\n");
    printf("       importTrusted | removeTrusted [options] <ImportRemoveFile>\n");
    printf("       importDisallowed | removeDisallowed [options] <ImportRemoveFile>\n");
    printf("       enumTrusted | enumDisallowed | enumDisallowedCTL [options] [<OutPemFile>]\n");
    printf("       importPfx [options] <InFile> <OutFile>\n");
    printf("       selfSignPfx [options] <conf string> <OutFile>\n");
    printf("                             file:<InFile> <OutFile>\n");
    printf("                             rsa <OutFile>\n");
    printf("                             ecc <OutFile>\n");
    printf("       isDisallowed [options] <InFile>\n");
    printf("       openPfx [options] <KeyId>\n");
    printf("       loadPfxEngine [options] <KeyId>\n");
    printf("       pemFromKeyId [options] <KeyId> <OutPemFile>\n");
    printf("       replaceKeyIdCerts [options] <KeyId> <ReplacePemFile> <OutFile>\n");
    printf("       verifyCert [options] <InCertFile> [<OutPemFile>]\n");
    printf("       displayCtl [options] <InCtlFile>\n");
    printf("Options are:\n");
    printf("  -p<string>            - password for importpfx\n");
    printf("  -c<string>            - cert format: der|pem|sst|ctl (default: der)\n");
    printf("  -e<string>            - engine path\n");
    printf("  -r<path>              - root path for certs and disallowed directories\n");
    printf("  -t<filename>          - traceLog file output. Default is stdout\n");
    printf("  -v<number>            - X509_VERIFY_PARAM_set_flags. For example, NO_CHECK_TIME: 0x200000\n");
    printf("  -K<count>             - KeyCount for loadPfxEngine\n");
    printf("  -I<count>             - InnerCount for loadPfxEngine\n");
    printf("  -S<milliseconds>      - Sleep milliseconds for loadPfxEngine\n");
    printf("  -excludeRoot\n");
    printf("  -excludeExtraCa\n");
    printf("  -excludeEnd\n");
    printf("  -disableTraceLogTest\n");
    printf("  -disableVerbose\n");
    printf("  -enableGdbusRpc\n");
    printf("  -disableTestPfxSecret\n");
    printf("  -h                    - This message\n");
    printf("\n");
}

#define MSCRYPTP_TEST_IMPORT_TRUSTED       1
#define MSCRYPTP_TEST_REMOVE_TRUSTED       2
#define MSCRYPTP_TEST_ENUM_TRUSTED         3
#define MSCRYPTP_TEST_IMPORT_DISALLOWED    4
#define MSCRYPTP_TEST_REMOVE_DISALLOWED    5
#define MSCRYPTP_TEST_ENUM_DISALLOWED      6
#define MSCRYPTP_TEST_IS_DISALLOWED        7
#define MSCRYPTP_TEST_IMPORT_PFX           8
#define MSCRYPTP_TEST_OPEN_PFX             9
#define MSCRYPTP_TEST_LOAD_PFX_ENGINE      10
#define MSCRYPTP_TEST_PEM_FROM_KEY_ID      11
#define MSCRYPTP_TEST_VERIFY_CERT          12
#define MSCRYPTP_TEST_SELF_SIGN_PFX        13
#define MSCRYPTP_TEST_REPLACE_KEY_ID_CERTS 14
#define MSCRYPTP_TEST_DISPLAY_CTL          15
#define MSCRYPTP_TEST_ENUM_DISALLOWED_CTL  16

static void _test_import_pfx(
    int mscryptFlags,
    int inLength,
    const unsigned char *inBytes,
    const char *password,
    const char *outFilename)
{
    const char *title = MSCRYPTP_TEST_TITLE;
    const char *loc = "";
    int ret = 0;
    int verifyChainError = 0;
    char *keyId = NULL;                 // MSCRYPT_clear_free_string()
    int keyIdLength = 0;
    BIO *out = NULL;

    printf("_test_import_pfx\n");

    printf("MSCRYPT_import_pfx_to_key_id\n");
    ret = MSCRYPT_import_pfx_to_key_id(
        NULL,                       // correlationId
        mscryptFlags,
        inLength,
        inBytes,
        password,
        &verifyChainError,
        &keyId);
    if (!ret) {
        printf("MSCRYPT_import_pfx_to_key_id FAILED\n");
        goto end;
    }

    if (ret < 0) {
        printf("MSCRYPT_import_pfx_to_key_id verifyChainError: %d 0x%x\n",
            verifyChainError, verifyChainError);
    }

    keyIdLength = (int) strlen(keyId);

    out = BIO_new_file(outFilename, "wb");
    if (out == NULL) {
        loc = "BIO_new_file";
        goto openSslErr;
    }

    if (BIO_write(out, keyId, keyIdLength) != keyIdLength) {
        loc = "BIO_write";
        goto openSslErr;
    }
    BIO_flush(out);

end:
    MSCRYPT_clear_free_string(keyId);
    BIO_free(out);
    return;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(NULL, 0, title, loc);
    goto end;
}

static const char _test_ecc_conf[] = 
    "[self_sign]\n"
    "sign_digest = sha256\n"
    "key_type = ecc\n"
    "ecc_curve = prime256v1     # also secp384r1 with sha384\n"
    "days = 365\n"
    "distinguished_name = dn\n"
    "x509_extensions = v3_ext\n"
    "\n"
    "[dn]\n"
    "C = US\n"
    "ST = Washington\n"
    "L = Redmond\n"
    "O = \"Microsoft Corporation\"\n"
    "1.CN = \"MSCrypt Test\"\n"
    "2.CN = \"MSCrypt Test Ecc\"\n"
    "\n"
    "[v3_ext]\n"
    "basicConstraints = critical,CA:FALSE\n"
    "extendedKeyUsage = critical,serverAuth,clientAuth\n"
    "subjectKeyIdentifier = hash\n"
    "authorityKeyIdentifier = keyid\n"
    "subjectAltName = @alt_names\n"
    "\n"
    "[alt_names]\n"
    "DNS.1 = test.mscrypt.microsoft.com\n"
    "DNS.2 = ecc.test.mscrypt.microsoft.com\n"
    "";


static const char _test_rsa_conf[] = 
    "[self_sign]\n"
    "sign_digest = sha256\n"
    "key_type = rsa\n"
    "rsa_bits = 2048\n"
    "rsa_exp = 0x10001          # also 0x3\n"
    "rsa_padding = 1            # 1 - RSA_PKCS1_PADDING 6 - RSA_PKCS1_PSS_PADDING\n"
    "days = 365\n"
    "distinguished_name = dn\n"
    "x509_extensions = v3_ext\n"
    "\n"
    "[dn]\n"
    "C = US\n"
    "ST = Washington\n"
    "L = Redmond\n"
    "O = \"Microsoft Corporation\"\n"
    "1.CN = \"MSCrypt Test\"\n"
    "2.CN = \"MSCrypt Test Rsa\"\n"
    "\n"
    "[v3_ext]\n"
    "basicConstraints = critical,CA:FALSE\n"
    "extendedKeyUsage = critical,serverAuth,clientAuth\n"
    "subjectKeyIdentifier = hash\n"
    "authorityKeyIdentifier = keyid\n"
    "subjectAltName = @alt_names\n"
    "\n"
    "[alt_names]\n"
    "DNS.1 = test.mscrypt.microsoft.com\n"
    "DNS.2 = rsa.test.mscrypt.microsoft.com\n"
    "";

static void _test_self_sign_pfx(
    int mscryptFlags,
    const char *confStr,
    const char *outFilename)
{
    const char *title = MSCRYPTP_TEST_TITLE;
    const char *loc = "";
    char *keyId = NULL;                 // MSCRYPT_clear_free_string()
    int keyIdLength = 0;
    BIO *out = NULL;

    printf("%s\n", __FUNCTION__);

    if (strcmp(confStr, "ecc") == 0) {
        confStr = _test_ecc_conf;
    } else if (strcmp(confStr, "rsa") == 0) {
        confStr = _test_rsa_conf;
    }

    if (!MSCRYPT_create_self_sign_pfx_to_key_id(
            NULL,
            mscryptFlags,
            confStr,
            &keyId)) {
        printf("MSCRYPT_create_self_sign_pfx_to_key_id FAILED\n");
        goto end;
    }

    keyIdLength = (int) strlen(keyId);

    out = BIO_new_file(outFilename, "wb");
    if (out == NULL) {
        loc = "BIO_new_file";
        goto openSslErr;
    }

    if (BIO_write(out, keyId, keyIdLength) != keyIdLength) {
        loc = "BIO_write";
        goto openSslErr;
    }
    BIO_flush(out);

end:
    MSCRYPT_clear_free_string(keyId);
    BIO_free(out);
    return;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(NULL, 0, title, loc);
    goto end;
}

static void _test_replace_key_id_certs(
    int mscryptFlags,
    const char *inKeyId,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    const char *outFilename)
{
    const char *title = MSCRYPTP_TEST_TITLE;
    const char *loc = "";
    char *outKeyId = NULL;                 // MSCRYPT_clear_free_string()
    int outKeyIdLength = 0;
    BIO *out = NULL;

    printf("%s\n", __FUNCTION__);

    if (!MSCRYPT_replace_key_id_certs(
            NULL,
            mscryptFlags,
            inKeyId,
            pemCertLength,
            pemCertBytes,
            &outKeyId)) {
        printf("MSCRYPT_create_self_sign_pfx_to_key_id FAILED\n");
        goto end;
    }

    outKeyIdLength = (int) strlen(outKeyId);

    out = BIO_new_file(outFilename, "wb");
    if (out == NULL) {
        loc = "BIO_new_file";
        goto openSslErr;
    }

    if (BIO_write(out, outKeyId, outKeyIdLength) != outKeyIdLength) {
        loc = "BIO_write";
        goto openSslErr;
    }
    BIO_flush(out);

end:
    MSCRYPT_clear_free_string(outKeyId);
    BIO_free(out);
    return;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(NULL, 0, title, loc);
    goto end;
}

static char *_little_endian_uni2asc(
    const unsigned char *uni,
    int unilen)
{
    int asclen, i;
    char *asctmp;
    /* string must contain an even number of bytes */
    if (unilen & 1)
        return NULL;
    asclen = unilen / 2;

    asctmp = MSCRYPT_zalloc(asclen + 1);
    if (asctmp == NULL)
        return NULL;

    for (i = 0; i < asclen; i++)
        asctmp[i] = uni[i * 2];

    return asctmp;
}

static void _test_display_ctl(
    int inLength,
    const unsigned char *inBytes)
{
    MSCRYPT_CTL *ctl = NULL;
    int aparamtype;
    const ASN1_OBJECT *aoid;
    const void *aparam;
    char oidstr[80];
    int i, j;

    BIO *bioOut = BIO_new_fp(stdout, BIO_NOCLOSE |  BIO_FP_TEXT);

    if (bioOut == NULL) {
        printf("BIO_new_fp failed\n");
        goto end;
    }

    ctl = MSCRYPT_CTL_parse(
        NULL,                           // correlationId
        inLength,
        inBytes);
    if (ctl == NULL) {
        printf("Error parsing CTL\n");
        goto end;
    }

    BIO_printf(bioOut, "version=");
    if (ctl->version)
        i2a_ASN1_INTEGER(bioOut, ctl->version);
    else
        BIO_puts(bioOut, "<NONE>");
    BIO_printf(bioOut, "\n");

    BIO_printf(bioOut, "subjectUsages=");
    for (i = 0; i < sk_ASN1_OBJECT_num(ctl->subjectUsages); i++) {
        if (i != 0)
            BIO_puts(bioOut, ", ");
        OBJ_obj2txt(oidstr, sizeof(oidstr), sk_ASN1_OBJECT_value(ctl->subjectUsages, i), 0);
        BIO_printf(bioOut, "%s", oidstr);
    }
    BIO_printf(bioOut, "\n");

    {
        ASN1_OBJECT *objtmp = NULL;
        int isDisallowed = 0;

        if (sk_ASN1_OBJECT_num(ctl->subjectUsages) == 1) {
            if ((objtmp = OBJ_txt2obj(szOID_DISALLOWED_LIST, 0)) != NULL) {
                if (OBJ_cmp(objtmp, sk_ASN1_OBJECT_value(ctl->subjectUsages, 0)) == 0) {
                    isDisallowed = 1;
                }

                ASN1_OBJECT_free(objtmp);
            }
        }

        if (!isDisallowed) {
            BIO_printf(bioOut, "NOT Disallowed subjectUsage\n");
        } else {
            BIO_printf(bioOut, "Disallowed subjectUsage\n");
        }
    }

    BIO_printf(bioOut, "listIdentifierBytes=");
    if (ctl->listIdentifier) {
        for (int i = 0; i < ctl->listIdentifier->length; i++)
            BIO_printf(bioOut, "%02x ", ctl->listIdentifier->data[i]); 
    } else
        BIO_puts(bioOut, "<NONE>");
    BIO_printf(bioOut, "\n");

    if (ctl->listIdentifier) {
        char *ascIdentifier = _little_endian_uni2asc(ctl->listIdentifier->data, ctl->listIdentifier->length);

        BIO_printf(bioOut, "listIdentifierString=");
        if (ascIdentifier)
            BIO_puts(bioOut, ascIdentifier);
        else
            BIO_puts(bioOut, "???");
        BIO_printf(bioOut, "\n");

        MSCRYPT_free(ascIdentifier);
    }

    BIO_printf(bioOut, "sequenceNumber=");
    if (ctl->sequenceNumber)
        i2a_ASN1_INTEGER(bioOut, ctl->sequenceNumber);
    else
        BIO_puts(bioOut, "<NONE>");
    BIO_printf(bioOut, "\n");

    BIO_printf(bioOut, "thisUpdate=");
    if (ctl->thisUpdate)
        ASN1_TIME_print(bioOut, ctl->thisUpdate);
    else
        BIO_puts(bioOut, "<NONE>");
    BIO_printf(bioOut, "\n");

    BIO_printf(bioOut, "nextUpdate=");
    if (ctl->nextUpdate)
        ASN1_TIME_print(bioOut, ctl->nextUpdate);
    else
        BIO_puts(bioOut, "<NONE>");
    BIO_printf(bioOut, "\n");
        
    BIO_printf(bioOut, "subjectAlgorithm=");
    X509_ALGOR_get0(&aoid, &aparamtype, &aparam, &ctl->subjectAlgorithm);
    OBJ_obj2txt(oidstr, sizeof(oidstr), aoid, 0);
    BIO_printf(bioOut, "%s\n", oidstr);

    {
        ASN1_OBJECT *objtmp = NULL;
        int isDisallowed = 0;

        if ((objtmp = OBJ_txt2obj(szOID_DISALLOWED_HASH, 0)) != NULL) {
            X509_ALGOR_get0(&aoid, &aparamtype, &aparam, &ctl->subjectAlgorithm);
            if (OBJ_cmp(objtmp, aoid) == 0) {
                isDisallowed = 1;
            }

            ASN1_OBJECT_free(objtmp);
        }

        if (!isDisallowed) {
            BIO_printf(bioOut, "NOT Disallowed subjectAlgorithm\n");
        } else {
            BIO_printf(bioOut, "Disallowed subjectAlgorithm\n");
        }
    }

    BIO_printf(bioOut, "----  Subjects  ----\n");
    for (i = 0; i < sk_MSCRYPT_CTL_SUBJECT_num(ctl->subjects); i++) {
        MSCRYPT_CTL_SUBJECT *psubject;

        BIO_printf(bioOut, "[%3d] : ", i);
        psubject = sk_MSCRYPT_CTL_SUBJECT_value(ctl->subjects, i);
        if (psubject == NULL) {
            BIO_printf(bioOut, "No Subject\n");
            continue;
        }

        if (psubject->subjectIdentifier.length != 0) {
            for (j = 0; j < psubject->subjectIdentifier.length; j++)
                BIO_printf(bioOut, "%02x", psubject->subjectIdentifier.data[j]); 
        } else
            BIO_puts(bioOut, "No Identifier");
        BIO_printf(bioOut, "\n");

        if (psubject->attributes == NULL)
            continue;

        // print_attribs(bioOut, psubject->attributes, "Attributes");
        BIO_printf(bioOut, "Has Attributes");
        BIO_printf(bioOut, "\n");
    }

    if (ctl->extensions == NULL || sk_X509_EXTENSION_num(ctl->extensions) <= 0)
        goto end;

    BIO_printf(bioOut, "----  Extensions  ----\n");
    for (i = 0; i < sk_X509_EXTENSION_num(ctl->extensions); i++) {
        ASN1_OBJECT *obj = NULL;
        X509_EXTENSION *ex = NULL;
        ASN1_OCTET_STRING *value = NULL;

        ex = sk_X509_EXTENSION_value(ctl->extensions, i);
        if (ex != NULL) {
            obj = X509_EXTENSION_get_object(ex);
        }

        if (obj == NULL) {
            BIO_printf(bioOut, "[%d] : NO OID\n", i);
            continue;
        }

        OBJ_obj2txt(oidstr, sizeof(oidstr), obj, 0);
        BIO_printf(bioOut, "[%d, %s] : ", i, oidstr);

        value = X509_EXTENSION_get_data(ex);
        if (value == NULL)
            BIO_puts(bioOut, "No Value");
        else if (value->length == 0)
            BIO_puts(bioOut, "Empty Value");
        else {
            for (int j = 0; j < value->length; j++)
                BIO_printf(bioOut, "%02x ", value->data[j]); 
        }
        BIO_printf(bioOut, "\n");
    }
    BIO_printf(bioOut, "\n");

end:
    MSCRYPT_CTL_free(ctl);
    BIO_free(bioOut);
}

static void _test_open_pfx(
    const char *keyId)
{
    int ret = 0;
    MSCRYPT_PFX_CTX *keyCtx = NULL;     // MSCRYPT_CLIENT_pfx_close()
    int pfxLength = 0;
    unsigned char *pfxBytes = NULL;     // MSCRYPT_free()
    char *salt = NULL;                  // MSCRYPT_clear_free_string()
    unsigned char from[32];
    unsigned char to[1024];
    unsigned char dgst[32];
    unsigned char sig[1024];
    unsigned int outSigLen = 0;

    printf("_test_open_pfx\n");

    ret = MSCRYPT_parse_pfx_engine_key_id(
        NULL,                           // correlationId
        keyId,
        &pfxLength,
        &pfxBytes,                      // MSCRYPT_free()
        &salt);
    if (!ret) {
        printf("MSCRYPT_parse_pfx_engine_key_id FAILED\n");
        goto end;
    }

    ret = MSCRYPT_CLIENT_pfx_open(
        NULL,                           // correlationId
        pfxLength,
        pfxBytes,
        salt,
        &keyCtx);
    if (!ret) {
        printf("MSCRYPT_CLIENT_pfx_open FAILED\n");
        goto end;
    }

    ret = MSCRYPT_CLIENT_rsa_private_encrypt(
        keyCtx,
        sizeof(from),
        from,
        sizeof(to),
        to,
        RSA_PKCS1_PADDING);

    if (ret <= 0) {
        printf("MSCRYPT_CLIENT_rsa_private_encrypt FAILED\n");
    } else {
        printf("MSCRYPT_CLIENT_rsa_private_encrypt signature length: %d\n", ret);
    }

    ret = MSCRYPT_CLIENT_ecdsa_sign(
        keyCtx,
        0,                  // type
        dgst,
        sizeof(dgst),
        sig,
        sizeof(sig),
        &outSigLen);
    if (!ret) {
        printf("MSCRYPT_CLIENT_ecdsa_sign FAILED\n");
    } else {
        printf("MSCRYPT_CLIENT_ecdsa_sign signature length: %d\n", outSigLen);
    }

end:
    MSCRYPT_free(pfxBytes);
    MSCRYPT_clear_free_string(salt);
    MSCRYPT_CLIENT_pfx_close(keyCtx);
    return;
}

static ENGINE *_test_load_engine_path(
    const char *enginePath,
    int executeFlags)
{
    const char *title = MSCRYPTP_TEST_TITLE;
    const char *loc = "";
    ENGINE *e = NULL;
    int engineInit = 0;

    ERR_clear_error();
    printf("%s\n", __FUNCTION__);

    ENGINE_load_dynamic();
    e = ENGINE_by_id("dynamic");
    if (e == NULL) {
        loc = "ENGINE_by_id";
        goto openSslErr;
    }

    if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", enginePath, 0)) {
        loc = "SO_PATH";
        goto openSslErr;
    }

    if (!ENGINE_ctrl_cmd_string(e, "ID", "mscryptpfx", 0)) {
        loc = "ID";
        goto openSslErr;
    }

    if (!ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
        loc = "LOAD";
        goto openSslErr;
    }

    if (!(ENGINE_init(e))) {
        loc = "ENGINE_init";
        goto openSslErr;
    }
    engineInit = 1;

    if (!ENGINE_ctrl_cmd(e, "execute_flags", executeFlags, NULL, 0, 0)) {
        loc = "execute_flags";
        goto openSslErr;
    }

end:
    return e;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(NULL, 0, title, loc);
    if (engineInit) {
        ENGINE_finish(e);   // for ENGINE_init()
    }
    ENGINE_free(e);
    e = NULL;
    goto end;
}

static EVP_PKEY *_test_load_engine_private_key(
    const char *engineKeyId,
    const char *enginePath,
    int executeFlags)
{
    const char *title = MSCRYPTP_TEST_TITLE;
    const char *loc = "";
    EVP_PKEY *pkey = NULL;

    // For _test_load_engine, only load once
    static ENGINE *e = NULL;

    if (e == NULL) {
        e = _test_load_engine_path(enginePath, executeFlags);
    }
    if (e == NULL) {
        goto end;
    }

    pkey = ENGINE_load_private_key(
        e,
        engineKeyId,
        NULL,               // *ui_method
        NULL);              // *callback_data
    if (pkey == NULL) {
        loc = "ENGINE_load_private_key";
        goto openSslErr;
    }

end:
#if 0
    // Keep one instance of the engine. Will leak the engine at process exit
    if (e != NULL) {
        ENGINE_finish(e);   // for ENGINE_init()
        ENGINE_free(e);     // for ENGINE_by_id()
    }
#endif
    return pkey;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(NULL, 0, title, loc);
    goto end;
}

static void _test_load_pfx_engine(
    int keyCount,
    int innerCount,
    int sleepMilliseconds,
    const char *keyId,
    const char *enginePath,
    int executeFlags)
{
    const char *title = MSCRYPTP_TEST_TITLE;
    const char *loc = "";
    int ret = 0;
    EVP_PKEY *pkey[256];

    unsigned char from[32];
    unsigned char to[1024];
    unsigned char encrypted[1024];
    unsigned char dgst[32];
    unsigned char sig[1024];
    unsigned int outSigLen = 0;
    int encryptedLen = 0;

    printf("_test_load_pfx_engine\n");
    if (keyCount < 1) {
        keyCount = 1;
    } else if (keyCount > ARRAY_SIZE(pkey)) {
        keyCount = ARRAY_SIZE(pkey);
    }
    memset(pkey, 0, sizeof(pkey));

    for (int i = 0; i < keyCount; i++) {
        if (enginePath != NULL) {
            pkey[i] = _test_load_engine_private_key(
                keyId,
                enginePath,
                executeFlags);
        } else {
            pkey[i] = MSCRYPT_load_engine_private_key(
                NULL,           // correlationId
                "mscryptpfx",
                keyId);
        }
        if (pkey[i] == NULL) {
            printf("load_engine_private_key FAILED\n");
            goto end;
        }
    }

    for (int i = 0; i < keyCount; i++) {
        for (int j = 0; j < innerCount; j++) {
            printf("----  Key[%d,%d] SleepMilliseconds[%d]  ----\n", i, j, sleepMilliseconds);
            if (sleepMilliseconds) {
                _my_sleep(sleepMilliseconds);
            }

            if (EVP_PKEY_id(pkey[i]) == EVP_PKEY_RSA) {
                RSA *rsa = EVP_PKEY_get0_RSA(pkey[i]);        // get0 doesn't up_ref
                if (!rsa) {
                    loc = "EVP_PKEY_get0_RSA";
                    goto openSslErr;
                }

                RAND_bytes(from, sizeof(from));

                ret = RSA_private_encrypt(
                    sizeof(from),
                    from,
                    to,
                    rsa,
                    RSA_PKCS1_PADDING);
                if (ret <= 0) {
                    loc = "RSA_private_encrypt";
                    printf("FAILED => %s\n\n", loc);
                    MSCRYPTP_trace_log_openssl_error(NULL, 0, title, loc);
                } else {
                    printf("RSA_private_encrypt signature length: %d\n", ret);
                }

                encryptedLen = RSA_public_encrypt(
                    sizeof(from),
                    from,
                    encrypted,
                    rsa,
                    RSA_PKCS1_OAEP_PADDING);
                if (encryptedLen <= 0) {
                    loc = "RSA_public_encrypt";
                    printf("FAILED => %s\n\n", loc);
                    MSCRYPTP_trace_log_openssl_error(NULL, 0, title, loc);
                } else {
                    printf("RSA_public_encrypt encrypted length: %d\n", encryptedLen);

                    ret = RSA_private_decrypt(
                        encryptedLen,
                        encrypted,
                        to,
                        rsa,
                        RSA_PKCS1_OAEP_PADDING);
                    if (ret <= 0) {
                        loc = "RSA_private_decrypt";
                        printf("FAILED => %s\n\n", loc);
                        MSCRYPTP_trace_log_openssl_error(NULL, 0, title, loc);
                    } else {
                        printf("RSA_private_decrypt decrypted length: %d\n", ret);

                        if (ret != sizeof(from) ||
                                0 != memcmp(to, from, sizeof(from))) {
                            printf("FAILED => decrypted != input\n");
                        } else {
                            printf("SUCCESS => decrypted == input\n");
                        }
                    }
                }

            } else if (EVP_PKEY_id(pkey[i]) == EVP_PKEY_EC) {
                EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(pkey[i]);   // get0 doesn't up_ref
                if (!eckey) {
                    loc = "EVP_PKEY_get0_EC_KEY";
                    goto openSslErr;
                }

                ret = ECDSA_sign(
                    0,                  // type
                    dgst,
                    sizeof(dgst),
                    sig,
                    &outSigLen,
                    eckey);
                if (!ret) {
                    loc = "ECDSA_sign";
                    printf("FAILED => %s\n\n", loc);
                    MSCRYPTP_trace_log_openssl_error(NULL, 0, title, loc);
                } else {
                    printf("ECDSA_sign signature length: %d\n", outSigLen);
                }
            } else {
                printf("Not RSA or EC\n");
                goto end;
            }
        }
    }

end:
    for (int i = 0; i < keyCount; i++) {
        EVP_PKEY_free(pkey[i]);
    }

    return;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(NULL, 0, title, loc);
}


static void _test_pem_from_key_id(
    int mscryptFlags,
    const char *keyId,
    const char *outFilename)
{
    const char *title = MSCRYPTP_TEST_TITLE;
    const char *loc = "";
    int ret = 0;
    int verifyChainError = 0;
    int pemCertLength = 0;
    char *pemCert = NULL;               // MSCRYPT_free()
    BIO *out = NULL;

    printf("%s\n", __FUNCTION__);

    ret = MSCRYPT_build_cert_chain_from_key_id(
        NULL,                           // correlationId
        mscryptFlags,
        keyId,
        &verifyChainError,
        &pemCertLength,                 // excludes NULL terminator
        &pemCert);
    if (!ret) {
        printf("MSCRYPT_build_cert_chain_from_key_id FAILED\n");
        goto end;
    }

    if (ret < 0) {
        printf("MSCRYPT_build_cert_chain_from_key_id verifyChainError: %d 0x%x\n",
            verifyChainError, verifyChainError);
    }

    out = BIO_new_file(outFilename, "wb");
    if (out == NULL) {
        loc = "BIO_new_file";
        goto openSslErr;
    }

    if (BIO_write(out, pemCert, pemCertLength) != pemCertLength) {
        loc = "BIO_write";
        goto openSslErr;
    }
    BIO_flush(out);

end:
    MSCRYPT_free(pemCert);
    BIO_free(out);
    return;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(NULL, 0, title, loc);
    goto end;
}

typedef struct test_verify_cert_arg_st TEST_VERIFY_CERT_ARG;
struct test_verify_cert_arg_st {
    const char *callerFunc;
};


static int _test_verify_cert_callback(
    const uuid_t correlationId,
    X509_STORE_CTX *storeCtx,
    int *verifyChainError,
    void *vArg)
{
    const char *title = MSCRYPTP_TEST_TITLE;
    const char *loc = "";
    int ret = 0;
    TEST_VERIFY_CERT_ARG *arg = (TEST_VERIFY_CERT_ARG *) vArg;
    STACK_OF(X509) *storeChain = NULL;
    int chainDepth = 0;

    printf("%s called by %s\n", __FUNCTION__, arg->callerFunc);

    if (*verifyChainError != 0) {
        printf("Callback verifyChainError: %d 0x%x\n",
            *verifyChainError, *verifyChainError);
    }

    storeChain = X509_STORE_CTX_get1_chain(storeCtx);
    if (storeChain == NULL) {
        loc = "CTX_get1_chain";
        goto openSslErr;
    }

    chainDepth = sk_X509_num(storeChain);
    printf("Callback chainDepth: %d\n", chainDepth);

    ret = 1;
end:
    sk_X509_pop_free(storeChain, X509_free);
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(NULL, 0, title, loc);
    goto end;
}


static void _test_verify_cert(
    unsigned long verifyFlags,
    int mscryptFlags,
    int certFormat,
    int inLength,
    const unsigned char *inBytes,
    const char *outFilename)    // optional
{
    const char *title = MSCRYPTP_TEST_TITLE;
    const char *loc = "";
    int ret = 0;
    int verifyChainError = 0;
    int pemCertLength = 0;
    char *pemCert = NULL;      // MSCRYPT_free()
    BIO *out = NULL;
    TEST_VERIFY_CERT_ARG argStruct;
    MSCRYPT_VERIFY_CERT_CTX *ctx = NULL;
    X509_VERIFY_PARAM *vpm = NULL;

    printf("%s\n", __FUNCTION__);

    ctx = MSCRYPT_create_verify_cert_ctx(NULL);
    if (ctx == NULL) {
        printf("MSCRYPT_create_verify_cert_ctx FAILED\n");
        goto end;
    }

    argStruct.callerFunc = __FUNCTION__;
    ret = MSCRYPT_register_verify_cert_callback(
        ctx,
        _test_verify_cert_callback,
        &argStruct);
    if (!ret) {
        printf("MSCRYPT_verify_cert FAILED\n");
        goto end;
    }

    if (verifyFlags != 0) {
        vpm = X509_VERIFY_PARAM_new();
        if (vpm == NULL) {
            loc = "X509_VERIFY_PARAM_new";
            goto openSslErr;
        }

        // X509_VERIFY_PARAM_set_inh_flags(vpm, X509_VP_FLAG_DEFAULT);      // The default
        // X509_VERIFY_PARAM_set_inh_flags(vpm, X509_VP_FLAG_OVERWRITE);    // To overwrite

        printf("X509_VERIFY_PARAM_set_flags: 0x%lx\n", verifyFlags);
        X509_VERIFY_PARAM_set_flags(vpm, verifyFlags);
        MSCRYPT_set_verify_cert_param(ctx, vpm);
    }

    ret = MSCRYPT_verify_cert(
        ctx,
        mscryptFlags,
        certFormat,
        inLength,
        inBytes,
        &verifyChainError,
        outFilename ? &pemCertLength : NULL,
        outFilename ? &pemCert : NULL);
    if (!ret) {
        printf("MSCRYPT_verify_cert FAILED\n");
        goto end;
    }

    if (ret < 0) {
        printf("MSCRYPT_verify_cert verifyChainError: %d 0x%x\n",
            verifyChainError, verifyChainError);
    } else {
        printf("MSCRYPT_verify_cert SUCCEEDED\n");
    }

    if (outFilename ) {
        out = BIO_new_file(outFilename, "wb");
        if (out == NULL) {
            loc = "BIO_new_file";
            goto openSslErr;
        }

        if (BIO_write(out, pemCert, pemCertLength) != pemCertLength) {
            loc = "BIO_write";
            goto openSslErr;
        }
        BIO_flush(out);
    }

end:
    MSCRYPT_free(pemCert);
    MSCRYPT_free_verify_cert_ctx(ctx);
    X509_VERIFY_PARAM_free(vpm);
    BIO_free(out);
    
    return;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(NULL, 0, title, loc);
    goto end;
}

static void _test_enum(
    int test,
    int mscryptFlags,
    const char *pemFilename)    // Optional
{
    const char *title = MSCRYPTP_TEST_TITLE;
    const char *loc = "";
    MSCRYPT_CERT_DIR *certDir = NULL;
    BIO *out = NULL;
    X509 *cert = NULL;

    if (test == MSCRYPTP_TEST_ENUM_TRUSTED) {
        printf("MSCRYPT_open_trusted_cert_dir\n");
        certDir = MSCRYPT_open_trusted_cert_dir(NULL, mscryptFlags);
    } else {
        printf("MSCRYPT_open_disallowed_cert_dir\n");
        certDir = MSCRYPT_open_disallowed_cert_dir(NULL, mscryptFlags);
    }

    if (certDir == NULL) {
        printf("MSCRYPT_open_cert_dir FAILED\n");
        goto end;
    }

    if (pemFilename ) {
        out = BIO_new_file(pemFilename, "w");
        if (out == NULL) {
            loc = "BIO_new_file";
            goto openSslErr;
        }
    }

    for (int i = 0;; i++) {
        int ret = 0;
        X509_free(cert);
        cert = NULL;

        ret = MSCRYPT_read_cert_dir(certDir, &cert);
        if (ret == 0) {
            printf("MSCRYPT_read_cert_dir FAILED\n");
        } else if (ret < 0 && i == 0) {
            printf("MSCRYPT_read_cert_dir => no certificates in directory\n");
        }

        if (ret <= 0) {
            break;
        }

        printf("  [%d]: ", i);
        X509_NAME_print_ex_fp(
            stdout,
            X509_get_subject_name(cert),
            0,                      // indent
            XN_FLAG_ONELINE | XN_FLAG_DN_REV);
        printf("\n");

        if (out) {
            if (!PEM_write_bio_X509(out, cert)) {
                loc = "PEM_write_bio_X509";
                goto openSslErr; 
            }
        }
    }

end:
    if (out) {
        BIO_flush(out);
        BIO_free(out);
    }

    X509_free(cert);
    MSCRYPT_close_cert_dir(certDir);
    return;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(NULL, 0, title, loc);
    goto end;
}

static void _test_enum_ctl(
    int mscryptFlags)
{
    MSCRYPT_CTL_DIR *ctlDir = NULL;
    int ctlLength = 0;
    unsigned char *ctlBytes = NULL;
    MSCRYPT_CTL *ctl = NULL;

    printf("MSCRYPT_open_disallowed_ctl_dir\n");
    ctlDir = MSCRYPT_open_disallowed_ctl_dir(NULL, mscryptFlags);

    if (ctlDir == NULL) {
        printf("MSCRYPT_open_ctl_dir FAILED\n");
        goto end;
    }

    for (int i = 0;; i++) {
        int ret = 0;
        char *ctlName = NULL;

        ctlLength = 0;
        MSCRYPT_free(ctlBytes);
        ctlBytes = NULL;
        MSCRYPT_CTL_free(ctl);
        ctl = NULL;

        ret = MSCRYPT_read_ctl_dir(ctlDir, &ctlLength, &ctlBytes);
        if (ret == 0) {
            printf("MSCRYPT_read_ctl_dir FAILED\n");
        } else if (ret < 0 && i == 0) {
            printf("MSCRYPT_read_ctl_dir => no ctls in directory\n");
        }

        if (ret <= 0) {
            break;
        }

        printf("  [%d]: ", i);

        ctl = MSCRYPT_CTL_parse(NULL, ctlLength, ctlBytes);
        if (ctl == NULL) {
            printf("MSCRYPT_CTL_parse failed\n");
            continue;
        }

        ctlName = MSCRYPT_CTL_format_name(NULL, ctl);
        if (ctlName == NULL) {
            printf("MSCRYPT_CTL_format_name failed\n");
            continue;
        }

        printf("%s\n", ctlName);
        MSCRYPT_free(ctlName);
    }

end:
    MSCRYPT_free(ctlBytes);
    MSCRYPT_CTL_free(ctl);
    MSCRYPT_close_ctl_dir(ctlDir);
    return;
}


static void _test_is_disallowed(
    int certFormat,
    int inLength,
    const unsigned char *inBytes)
{
    const char *title = MSCRYPTP_TEST_TITLE;
    const char *loc = "";
    int ret = 0;
    X509 *cert = NULL;

    ERR_clear_error();

    printf("%s\n", __FUNCTION__);
    switch (certFormat) {
        case MSCRYPT_CERT_FORMAT_DER:
            cert = d2i_X509(NULL, &inBytes, inLength);
            break;
        case MSCRYPT_CERT_FORMAT_PEM:
            {
                BIO *in = BIO_new_mem_buf(inBytes, inLength);
                if (in != NULL) {
                    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
                    BIO_free(in);
                }
            }
            break;
        case MSCRYPT_CERT_FORMAT_SST:
        default:
            printf("Don't support sst format type\n");
            return;
    }

    if (cert == NULL) {
        loc = "DecodeCert";
        goto openSslErr;
    }

    ret = MSCRYPT_is_disallowed_cert(
        NULL,           // correlationId
        cert);
    if (ret)
        printf("Disallowed cert\n");
    else
        printf("Allowed cert\n");

end:
    X509_free(cert);
    return;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(NULL, 0, title, loc);
    goto end;
}

#ifdef MSCRYPT_TEST_WINDOWS
int mscrypt_main(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
    int test = 0;
    int ret = 0;
    uuid_t correlationId;
    const char *enginePath = NULL;
    const char *traceLogFilename = NULL;
    const char *inFilenameOrKeyId = NULL;
    const char *outOrPemFilename = NULL;
    const char *replaceOutFilename = NULL;
    int mscryptFlags = 0;
    int certFormat = MSCRYPT_CERT_FORMAT_DER;
    const char *password = NULL;
    BIO *in = NULL;
    BIO *mem = NULL;
    int inLength;
    unsigned char *inBytes;       // Don't free
    int executeFlags = MSCRYPTP_IN_PROC_EXECUTE_FLAG |
                        MSCRYPTP_TRACE_LOG_TEST_EXECUTE_FLAG |
                        MSCRYPTP_TRACE_LOG_VERBOSE_EXECUTE_FLAG |
                        MSCRYPTP_TEST_PFX_SECRET_EXECUTE_FLAG;
    const char *defaultCertArea = NULL;
    int keyCount = 1;
    int innerCount = 1;
    int sleepMilliseconds = 0;
    unsigned long verifyFlags = 0;

    if (argc < 2)
#ifdef MSCRYPT_TEST_WINDOWS
        return 0;
#else
        goto BadUsage;
#endif

    if (strcasecmp(argv[1], "importTrusted") == 0)
        test = MSCRYPTP_TEST_IMPORT_TRUSTED;
    else if (strcasecmp(argv[1], "removeTrusted") == 0)
        test = MSCRYPTP_TEST_REMOVE_TRUSTED;
    else if (strcasecmp(argv[1], "enumTrusted") == 0)
        test = MSCRYPTP_TEST_ENUM_TRUSTED;
    else if (strcasecmp(argv[1], "importDisallowed") == 0)
        test = MSCRYPTP_TEST_IMPORT_DISALLOWED;
    else if (strcasecmp(argv[1], "removeDisallowed") == 0)
        test = MSCRYPTP_TEST_REMOVE_DISALLOWED;
    else if (strcasecmp(argv[1], "enumDisallowed") == 0)
        test = MSCRYPTP_TEST_ENUM_DISALLOWED;
    else if (strcasecmp(argv[1], "isDisallowed") == 0)
        test = MSCRYPTP_TEST_IS_DISALLOWED;
    else if (strcasecmp(argv[1], "enumDisallowedCtl") == 0)
        test = MSCRYPTP_TEST_ENUM_DISALLOWED_CTL;
    else if (strcasecmp(argv[1], "importPfx") == 0)
        test = MSCRYPTP_TEST_IMPORT_PFX;
    else if (strcasecmp(argv[1], "openPfx") == 0)
        test = MSCRYPTP_TEST_OPEN_PFX;
    else if (strcasecmp(argv[1], "loadPfxEngine") == 0)
        test = MSCRYPTP_TEST_LOAD_PFX_ENGINE;
    else if (strcasecmp(argv[1], "pemFromKeyId") == 0)
        test = MSCRYPTP_TEST_PEM_FROM_KEY_ID;
    else if (strcasecmp(argv[1], "verifyCert") == 0)
        test = MSCRYPTP_TEST_VERIFY_CERT;
    else if (strcasecmp(argv[1], "selfSignPfx") == 0)
        test = MSCRYPTP_TEST_SELF_SIGN_PFX;
    else if (strcasecmp(argv[1], "replaceKeyIdCerts") == 0)
        test = MSCRYPTP_TEST_REPLACE_KEY_ID_CERTS;
    else if (strcasecmp(argv[1], "displayCtl") == 0)
        test = MSCRYPTP_TEST_DISPLAY_CTL;
    else
#ifdef MSCRYPT_TEST_WINDOWS
        return 0;
#else
        goto BadUsage;
#endif


    RAND_bytes(correlationId, sizeof(correlationId));

    --argc;
    ++argv;

    while (--argc > 0)
    {
        if (**++argv == '-')
        {
            if (strcasecmp(argv[0]+1, "excludeRoot") == 0)
                mscryptFlags |= MSCRYPT_EXCLUDE_ROOT_FLAG;
            else if (strcasecmp(argv[0]+1, "excludeExtraCa") == 0)
                mscryptFlags |= MSCRYPT_EXCLUDE_EXTRA_CA_FLAG;
            else if (strcasecmp(argv[0]+1, "excludeEnd") == 0)
                mscryptFlags |= MSCRYPT_EXCLUDE_END_FLAG;
            else if (strcasecmp(argv[0]+1, "disableTraceLogTest") == 0)
                executeFlags &= ~MSCRYPTP_TRACE_LOG_TEST_EXECUTE_FLAG;
            else if (strcasecmp(argv[0]+1, "disableVerbose") == 0)
                executeFlags &= ~MSCRYPTP_TRACE_LOG_VERBOSE_EXECUTE_FLAG;
            else if (strcasecmp(argv[0]+1, "enableGdbusRpc") == 0)
                executeFlags &= ~MSCRYPTP_IN_PROC_EXECUTE_FLAG;
            else if (strcasecmp(argv[0]+1, "disableTestPfxSecret") == 0)
                executeFlags &= ~MSCRYPTP_TEST_PFX_SECRET_EXECUTE_FLAG;
            else {
                switch(argv[0][1])
                {
                    case 'p':
                        password = argv[0]+2;
                        break;
                    case 'e':
                        enginePath = argv[0]+2;
                        break;
                    case 'r':
                        defaultCertArea = argv[0]+2;
                        break;
                    case 't':
                        traceLogFilename = argv[0]+2;
                        executeFlags |= MSCRYPTP_TRACE_LOG_TEST_EXECUTE_FLAG;
                        break;
                    case 'c':
                        if (strcasecmp(argv[0]+2, "der") == 0)
                            certFormat = MSCRYPT_CERT_FORMAT_DER;
                        else if (strcasecmp(argv[0]+2, "pem") == 0)
                            certFormat = MSCRYPT_CERT_FORMAT_PEM;
                        else if (strcasecmp(argv[0]+2, "sst") == 0)
                            certFormat = MSCRYPT_CERT_FORMAT_SST;
                        else if (strcasecmp(argv[0]+2, "ctl") == 0)
                            certFormat = MSCRYPT_CERT_FORMAT_CTL;
                        else {
                            printf("Invalid cert format\n");
                            goto BadUsage;
                        }
                        break;
                    case 'v':
                        verifyFlags = strtoul(argv[0]+2, NULL, 0);
                        break;
                    case 'K':
                        keyCount = strtol(argv[0]+2, NULL, 0);
                        break;
                    case 'I':
                        innerCount = strtol(argv[0]+2, NULL, 0);
                        break;
                    case 'S':
                        sleepMilliseconds = strtol(argv[0]+2, NULL, 0);
                        break;

                    case 'h':
                    default:
                        goto BadUsage;
                }
            }
        } else {
            if (inFilenameOrKeyId == NULL)
                inFilenameOrKeyId = argv[0];
            else if (outOrPemFilename == NULL)
                outOrPemFilename = argv[0];
            else if (replaceOutFilename == NULL)
                replaceOutFilename = argv[0];
            else {
                printf("Extra filenames\n");
                goto BadUsage;
            }
        }
    }

    if (test == MSCRYPTP_TEST_ENUM_TRUSTED ||
            test == MSCRYPTP_TEST_ENUM_DISALLOWED |
            test == MSCRYPTP_TEST_ENUM_DISALLOWED_CTL) {
        outOrPemFilename = inFilenameOrKeyId;
    } else if (inFilenameOrKeyId == NULL) {
        printf("Missing inFilenameOrKeyId\n");
        goto BadUsage;
    }

    if (test == MSCRYPTP_TEST_IMPORT_PFX ||
            test == MSCRYPTP_TEST_PEM_FROM_KEY_ID ||
            test == MSCRYPTP_TEST_SELF_SIGN_PFX ||
            test == MSCRYPTP_TEST_REPLACE_KEY_ID_CERTS) {
        if (outOrPemFilename == NULL) {
            printf("Missing outOrPemFilename\n");
            goto BadUsage;
        }
    }

    if (test == MSCRYPTP_TEST_REPLACE_KEY_ID_CERTS) {
        if (replaceOutFilename == NULL) {
            printf("Missing replaceOutFilename\n");
            goto BadUsage;
        }
    }

    MSCRYPTP_set_execute_flags(executeFlags);
    if (traceLogFilename != NULL) {
        MSCRYPTP_set_trace_log_filename(traceLogFilename);
    }


    if (defaultCertArea && *defaultCertArea) {
        size_t defaultCertDirLength = strlen(defaultCertArea) + strlen("/certs") + 1;
        char *defaultCertDir = MSCRYPT_zalloc(defaultCertDirLength);
        if (defaultCertDir == NULL) {
            printf("Allocation Error\n");
            goto BadUsage;
        }

        BIO_snprintf(defaultCertDir, defaultCertDirLength, "%s/certs",
            defaultCertArea);

        MSCRYPTP_set_default_dir(
            defaultCertArea,
            defaultCertDir);

        MSCRYPT_free(defaultCertDir);
    }

    if ((executeFlags & MSCRYPTP_TEST_PFX_SECRET_EXECUTE_FLAG) == 0) {
        printf("----  MSCRYPTP_install_image_certs  ----\n");
        if (!MSCRYPTP_install_image_certs(correlationId)) {
            printf("MSCRYPTP_install_image_certs FAILED\n");
        }

        printf("----  MSCRYPTP_create_pfx_secret  ----\n");
        if (!MSCRYPTP_create_pfx_secret(correlationId)) {
            printf("MSCRYPTP_create_pfx_secret FAILED\n");
        }
    }

    if (test == MSCRYPTP_TEST_IMPORT_TRUSTED ||
            test == MSCRYPTP_TEST_REMOVE_TRUSTED ||
            test == MSCRYPTP_TEST_IMPORT_DISALLOWED ||
            test == MSCRYPTP_TEST_REMOVE_DISALLOWED ||
            test == MSCRYPTP_TEST_IS_DISALLOWED ||
            test == MSCRYPTP_TEST_IMPORT_PFX ||
            test == MSCRYPTP_TEST_VERIFY_CERT ||
            test == MSCRYPTP_TEST_REPLACE_KEY_ID_CERTS ||
            test == MSCRYPTP_TEST_DISPLAY_CTL) {
        const char *newFilename = inFilenameOrKeyId;
        if (test == MSCRYPTP_TEST_REPLACE_KEY_ID_CERTS) {
            newFilename = outOrPemFilename;
        }

        in = BIO_new_file(newFilename, "rb");
        if (in == NULL) {
            printf("Failed BIO_new_file: %s\n", newFilename);
            goto end;
        }
        mem = BIO_new(BIO_s_mem());
        if (mem == NULL) {
            printf("Out of Memory\n");
            goto end;
        }

        for (;;) {
            char buff[512];
            int inl = BIO_read(in, buff, sizeof(buff));

            if (inl <= 0)
                break;
            if (BIO_write(mem, buff, inl) != inl) {
                printf("Out of Memory\n");
                goto end;
            }
        }

        inLength = (int) BIO_get_mem_data(mem, (char **) &inBytes);
        printf("filename: %s Length: %d\n", newFilename, inLength);
    }

    switch (test) {
        case MSCRYPTP_TEST_IMPORT_TRUSTED:
            printf("MSCRYPT_import_trusted_certs\n");
            ret = MSCRYPT_import_trusted_certs(
                NULL,                       // correlationId
                NULL,                       // sharedMem
                certFormat,
                inLength,
                inBytes);
            if (!ret)
                printf("MSCRYPT_import_trusted_certs FAILED\n");
            break;

        case MSCRYPTP_TEST_REMOVE_TRUSTED:
            printf("MSCRYPT_remove_trusted_certs\n");
            ret = MSCRYPT_remove_trusted_certs(
                NULL,                       // correlationId
                NULL,                       // sharedMem
                certFormat,
                inLength,
                inBytes);
            if (!ret)
                printf("MSCRYPT_remove_trusted_certs FAILED\n");
            break;

        case MSCRYPTP_TEST_IMPORT_DISALLOWED:
            {
                MSCRYPT_SHARED_MEM *sharedMem = NULL;
                unsigned char *disallowedInBytes = NULL;

                printf("MSCRYPT_open_shared_mem\n");
                sharedMem = MSCRYPT_open_shared_mem(
                    NULL,                       // correlationId
                    inLength,
                    &disallowedInBytes);
                if (sharedMem == NULL) {
                    printf("MSCRYPT_open_shared_mem FAILED\n");
                    disallowedInBytes = inBytes;
                } else {
                    memcpy(disallowedInBytes, inBytes, inLength);
                }

                printf("MSCRYPT_import_disallowed_certs\n");
                ret = MSCRYPT_import_disallowed_certs(
                    NULL,                       // correlationId
                    sharedMem,
                    certFormat,
                    inLength,
                    disallowedInBytes);
                if (!ret)
                    printf("MSCRYPT_import_disallowed_certs FAILED\n");

                if (sharedMem) {
                    printf("MSCRYPT_close_shared_mem\n");
                    MSCRYPT_close_shared_mem(sharedMem);
                }
            }
            break;

        case MSCRYPTP_TEST_REMOVE_DISALLOWED:
            printf("MSCRYPT_remove_disallowed_certs\n");
            ret = MSCRYPT_remove_disallowed_certs(
                NULL,                       // correlationId
                NULL,                       // sharedMem
                certFormat,
                inLength,
                inBytes);
            if (!ret)
                printf("MSCRYPT_remove_disallowed_certs FAILED\n");
            break;

        case MSCRYPTP_TEST_ENUM_TRUSTED:
        case MSCRYPTP_TEST_ENUM_DISALLOWED:
            _test_enum(
                test,
                mscryptFlags,
                outOrPemFilename);
            break;

        case MSCRYPTP_TEST_ENUM_DISALLOWED_CTL:
            _test_enum_ctl(
                mscryptFlags);
            break;

        case MSCRYPTP_TEST_IS_DISALLOWED:
            _test_is_disallowed(
                certFormat,
                inLength,
                inBytes);
            break;

        case MSCRYPTP_TEST_IMPORT_PFX:
            _test_import_pfx(
                mscryptFlags,
                inLength,
                inBytes,
                password,
                outOrPemFilename);
            break;

        case MSCRYPTP_TEST_OPEN_PFX:
            _test_open_pfx(
                inFilenameOrKeyId);
            break;

        case MSCRYPTP_TEST_LOAD_PFX_ENGINE:
            _test_load_pfx_engine(
                keyCount,
                innerCount,
                sleepMilliseconds,
                inFilenameOrKeyId,
                enginePath,
                executeFlags);
            break;

        case MSCRYPTP_TEST_PEM_FROM_KEY_ID:
            _test_pem_from_key_id(
                mscryptFlags,
                inFilenameOrKeyId,
                outOrPemFilename);
            break;

        case MSCRYPTP_TEST_VERIFY_CERT:
            _test_verify_cert(
                verifyFlags,
                mscryptFlags,
                certFormat,
                inLength,
                inBytes,
                outOrPemFilename);
            break;

        case MSCRYPTP_TEST_SELF_SIGN_PFX:
            _test_self_sign_pfx(
                mscryptFlags,
                inFilenameOrKeyId,
                outOrPemFilename);
            break;

        case MSCRYPTP_TEST_REPLACE_KEY_ID_CERTS:
            _test_replace_key_id_certs(
                mscryptFlags,
                inFilenameOrKeyId,
                inLength,
                inBytes,
                replaceOutFilename);
            break;

        case MSCRYPTP_TEST_DISPLAY_CTL:
            _test_display_ctl(
                inLength,
                inBytes);
            break;

        default:
            printf("Invalid test\n");
    }

end:
    BIO_free(in);
    BIO_free(mem);
    return 1;

BadUsage:
    Usage();
    return 1;
}
