// #define MSCRYPT_TEST_WINDOWS 1

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include "mscryptcurl.h"
#include "mscryptp.h"

#ifdef MSCRYPT_TEST_WINDOWS
#define strcasecmp _stricmp
#endif

static void Usage(void)
{
    printf("Usage:\n");
    printf("       curlUrl [options] <Url_1> ... <Url_N>\n");
    printf("Options are:\n");
    printf("  -p<string>            - pemFilename\n");
    printf("  -k<string>            - mscryptpfx keyId\n");
    printf("  -r<path>              - root path for certs and disallowed directories\n");
    printf("  -t<filename>          - traceLog file output. Default is stdout\n");
    printf("  -w<filename>          - write output to file\n");
    printf("  -c<filename>          - write certs to file\n");
    printf("  -disableTraceLogTest\n");
    printf("  -disableVerbose\n");
    printf("  -enableGdbusRpc\n");
    printf("  -disableTestPfxSecret\n");
    printf("  -disableVerifyHost\n");
    printf("  -disableVerifyPeer\n");
    printf("  -v                    - verbose\n");
    printf("  -h                    - This message\n");
    printf("\n");
}

#define MSCRYPTP_CURL_TEST_URL              1


static int _curl_test_verify_cert_callback(
    const uuid_t correlationId,
    X509_STORE_CTX *storeCtx,
    int *verifyChainError,
    void *arg)
{
    const char *title = MSCRYPTP_TEST_TITLE;
    const char *loc = "";
    int ret = 0;
    const char *certFilename = (const char *) arg;
    STACK_OF(X509) *storeChain = NULL;
    int chainDepth = 0;
    int pemCertLength = 0;
    char *pemCert = NULL;       // MSCRYPT_free()
    BIO *out = NULL;

    printf("%s\n", __FUNCTION__);

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

    for (int i = 0; i < chainDepth; i++) {
        X509 *cert = sk_X509_value(storeChain, i);
        printf("  [%d]: ", i);
        X509_NAME_print_ex_fp(
            stdout,
            X509_get_subject_name(cert),
            0,                      // indent
            XN_FLAG_ONELINE);
        printf("\n");
    }

    if (certFilename) {
        if (!MSCRYPTP_pem_from_certs(
                correlationId,
                NULL,                   // X509 *cert
                storeChain,
                &pemCertLength,
                &pemCert)) {
            printf("MSCRYPTP_pem_from_certs FAILED\n");
            goto end;
        }

        out = BIO_new_file(certFilename, "wb");
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

    ret = 1;
end:
    BIO_free(out);
    sk_X509_pop_free(storeChain, X509_free);
    MSCRYPT_free(pemCert);
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}
static
size_t
_write_memory_callback(
    void *contents,
    size_t size,
    size_t nmemb,
    void *userp)
{
    size_t realSize = size * nmemb;
    BIO *out = (BIO *) userp;

    printf("_write_memory_callback size: %d nmemb: %d\n", (int) size, (int) nmemb);
    if (out) {
        if (BIO_write(out, contents, (int) realSize) != (int) realSize) {
            MSCRYPTP_trace_log_openssl_error(NULL, 0, MSCRYPTP_TEST_TITLE, "BIO_write");
        }
    }

    return realSize;
}


#define MSCRYPTP_CURL_MAX_URL_COUNT     32

#ifdef MSCRYPT_TEST_WINDOWS
int mscryptcurl_main(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
    CURL *curl = NULL;
    CURLcode ret;
    int test = 0;
    uuid_t correlationId;
    const char *pemFilename = NULL;
    const char *engineKeyId = NULL;
    const char *traceLogFilename = NULL;
    const char *writeFilename = NULL;
    const char *certFilename = NULL;
    const char *url[MSCRYPTP_CURL_MAX_URL_COUNT];
    int urlCount = 0;
    int executeFlags = MSCRYPTP_IN_PROC_EXECUTE_FLAG |
                        MSCRYPTP_TRACE_LOG_TEST_EXECUTE_FLAG |
                        MSCRYPTP_TRACE_LOG_VERBOSE_EXECUTE_FLAG |
                        MSCRYPTP_TEST_PFX_SECRET_EXECUTE_FLAG;
    const char *defaultCertArea = NULL;
    int verbose = 0;
    int disableVerifyHost = 0;
    int disableVerifyPeer = 0;
    BIO *out = NULL;
    MSCRYPT_VERIFY_CERT_CTX *ctx = NULL;

    if (argc < 2)
#ifdef MSCRYPT_TEST_WINDOWS
        return 0;
#else
        goto BadUsage;
#endif

    if (strcasecmp(argv[1], "curlUrl") == 0)
        test = MSCRYPTP_CURL_TEST_URL;
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
            if (strcasecmp(argv[0]+1, "disableTraceLogTest") == 0)
                executeFlags &= ~MSCRYPTP_TRACE_LOG_TEST_EXECUTE_FLAG;
            else if (strcasecmp(argv[0]+1, "disableVerbose") == 0)
                executeFlags &= ~MSCRYPTP_TRACE_LOG_VERBOSE_EXECUTE_FLAG;
            else if (strcasecmp(argv[0]+1, "enableGdbusRpc") == 0)
                executeFlags &= ~MSCRYPTP_IN_PROC_EXECUTE_FLAG;
            else if (strcasecmp(argv[0]+1, "disableTestPfxSecret") == 0)
                executeFlags &= ~MSCRYPTP_TEST_PFX_SECRET_EXECUTE_FLAG;
            else if (strcasecmp(argv[0]+1, "disableVerifyHost") == 0)
                disableVerifyHost = 1;
            else if (strcasecmp(argv[0]+1, "disableVerifyPeer") == 0)
                disableVerifyPeer = 1;
            else {
                switch(argv[0][1])
                {
                    case 'p':
                        pemFilename = argv[0]+2;
                        break;
                    case 'k':
                        engineKeyId = argv[0]+2;
                        break;
                    case 'r':
                        defaultCertArea = argv[0]+2;
                        break;
                    case 't':
                        traceLogFilename = argv[0]+2;
                        executeFlags |= MSCRYPTP_TRACE_LOG_TEST_EXECUTE_FLAG;
                        break;
                    case 'w':
                        writeFilename = argv[0]+2;
                        break;
                    case 'c':
                        certFilename = argv[0]+2;
                        break;
                    case 'v':
                        verbose = 1;
                        break;
                    case 'h':
                    default:
                        goto BadUsage;
                }
            }
        } else {
            if (urlCount < MSCRYPTP_CURL_MAX_URL_COUNT) {
                url[urlCount++] = argv[0];
            } else {
                printf("Exceeded max url count: %d\n", MSCRYPTP_CURL_MAX_URL_COUNT);
                goto BadUsage;
            }
        }
    }

    if (urlCount == 0) {
        printf("Missing Urls\n");
        goto BadUsage;
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

    curl = curl_easy_init();
    if (curl == NULL) {
        printf("curl_easy_init() FAILED\n");
        goto end;
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

    if (verbose || certFilename) {
        if (certFilename) {
            printf("MSCRYPT_register_verify_cert_callback save pem certs to: %s\n", certFilename);
        } else {
            printf("MSCRYPT_register_verify_cert_callback\n");
        }
        ctx = MSCRYPT_create_verify_cert_ctx(NULL);
        if (ctx == NULL) {
            printf("MSCRYPT_create_verify_cert_ctx FAILED\n");
            goto end;
        }

        if (!MSCRYPT_register_verify_cert_callback(
                ctx,
                _curl_test_verify_cert_callback,
                (void*) certFilename)) {
            printf("MSCRYPT_verify_cert FAILED\n");
            goto end;
        }
    }

    ret = MSCRYPT_curl_setopt_ssl_client(
        curl,
        ctx,
        pemFilename,
        engineKeyId ? "mscryptpfx" : NULL,
        engineKeyId);
    if (ret != CURLE_OK) {
        printf("MSCRYPT_curl_setopt_ssl_client failed: %d %s\n",
            ret,
            curl_easy_strerror(ret));
        goto end;
    }

    if (disableVerifyHost) {
        printf("disableVerifyHost\n");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
    }

    if (disableVerifyPeer) {
        printf("disableVerifyPeer\n");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    }

    if (writeFilename) {
        out = BIO_new_file(writeFilename, "wb");
        if (out == NULL) {
            MSCRYPTP_trace_log_openssl_error_para(NULL, 0, MSCRYPTP_TEST_TITLE, "BIO_new_file",
                "filename: %s", writeFilename);
            goto end;
        }
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _write_memory_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)out);

    for (int i = 0; i < urlCount; i++) {
        char errbuf[CURL_ERROR_SIZE];
        printf("----  URL[%d - %s]  ----\n", i, url[i]);
        ret = curl_easy_setopt(curl, CURLOPT_URL, url[i]);
        if (ret != CURLE_OK) {
            printf("CURLOPT_URL: %d %s\n",
                ret,
                curl_easy_strerror(ret));
            break;
        }

        if (verbose) {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }

        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
        errbuf[0] = 0;

        ret = curl_easy_perform(curl);
        if (ret != CURLE_OK) {
            printf("curl_easy_perform: %d %s\n",
                ret,
                curl_easy_strerror(ret));
            if (errbuf[0]) {
                printf("  %s\n", errbuf);
            }
        }
    }



end:
    if (out) {
        BIO_flush(out);
        BIO_free(out);
    }
    if (curl != NULL) {
        curl_easy_cleanup(curl);
    }

    MSCRYPT_free_verify_cert_ctx(ctx);
    return 1;

BadUsage:
    Usage();
    return 1;
}
