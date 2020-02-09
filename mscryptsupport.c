#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifndef MSCRYPT_TEST_WINDOWS
#include <sys/time.h>
#include <syslog.h>
#else
#define LOG_EMERG   0   /* system is unusable */
#define LOG_ALERT   1   /* action must be taken immediately */
#define LOG_CRIT    2   /* critical conditions */
#define LOG_ERR     3   /* error conditions */
#define LOG_WARNING 4   /* warning conditions */
#define LOG_NOTICE  5   /* normal but significant condition */
#define LOG_INFO    6   /* informational */
#define LOG_DEBUG   7   /* debug-level messages */    
#endif
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include "mscryptp.h"

#ifdef MSCRYPT_TEST_WINDOWS
#include <windows.h>
struct timeval {
    int     tv_sec;     /* seconds */
    int     tv_usec;    /* microseconds */
};

struct timezone {
    int     tz_minuteswest;     /* minutes west of Greenwich */
    int     tz_dsttime;         /* type of DST correction */
};

int gettimeofday(
    struct timeval *tv,
    struct timezone *tz)
{
    FILETIME ftCurrent;
    DWORDLONG nano_100;

    GetSystemTimeAsFileTime(&ftCurrent);
    memcpy(&nano_100, &ftCurrent, sizeof(nano_100));

    tv->tv_sec = (int) (nano_100 / 10000000i64);
    tv->tv_usec = (int) ((nano_100 / 10i64) % 1000000i64);

    return 0;
}
#endif

//
// MSCRYPT memory functions
//

void* MSCRYPT_zalloc(
    size_t num)
{
    const char *title = MSCRYPTP_MEMORY_ALLOC_TITLE;
    void *mem = OPENSSL_zalloc(num);
    if (mem == NULL) {
        MSCRYPTP_trace_log_openssl_error(NULL, 0, title, NULL);
    }

    return mem;
}

void* MSCRYPT_realloc(
    void *mem,
    size_t num)
{
    const char *title = MSCRYPTP_MEMORY_ALLOC_TITLE;
    void *newMem = OPENSSL_realloc(mem, num);
    if (newMem == NULL) {
        MSCRYPTP_trace_log_openssl_error(NULL, 0, title, NULL);
    }

    return newMem;
}

void MSCRYPT_free(
    void *mem)
{
    OPENSSL_free(mem);
}


void MSCRYPT_clear_free(
    void *mem,
    size_t num)
{
    OPENSSL_clear_free(mem, num);
}

void MSCRYPT_clear_free_string(
    char *str)
{
    if (str != NULL) {
        MSCRYPT_clear_free(str, strlen(str));
    }
}

void MSCRYPT_cleanse(
    void *mem,
    size_t num)
{
    OPENSSL_cleanse(mem, num);
}

char *MSCRYPT_strdup(
    const char *str)
{
    const char *title = MSCRYPTP_MEMORY_ALLOC_TITLE;
    char *dup = OPENSSL_strdup(str);
    if (dup == NULL) {
        MSCRYPTP_trace_log_openssl_error(NULL, 0, title, NULL);
    }

    return dup;
}

//
// MSCRYPT configuration functions. Mainly to configure for testing
//


void MSCRYPTP_set_execute_flags(
    int flags)
{
    if (flags & MSCRYPTP_IN_PROC_EXECUTE_FLAG) {
        MSCRYPTP_inProc = 1;
    }

    if (flags & MSCRYPTP_TRACE_LOG_TEST_EXECUTE_FLAG) {
        MSCRYPTP_traceLogTest = 1;
    }

    if (flags & MSCRYPTP_TRACE_LOG_VERBOSE_EXECUTE_FLAG) {
        MSCRYPTP_traceLogVerbose = 1;
    }

    if (flags & MSCRYPTP_TEST_PFX_SECRET_EXECUTE_FLAG) {
        MSCRYPTP_useTestPfxSecret = 1;
    }
}


static char *MSCRYPTP_defaultCertArea;
static char *MSCRYPTP_defaultCertDir;

void MSCRYPTP_set_default_dir(
    const char *defaultCertArea,
    const char *defaultCertDir)
{
    if (defaultCertArea && *defaultCertArea) {
        MSCRYPT_free(MSCRYPTP_defaultCertArea);
        MSCRYPTP_defaultCertArea = MSCRYPT_strdup(defaultCertArea);
    }

    if (defaultCertDir && *defaultCertDir) {
        MSCRYPT_free(MSCRYPTP_defaultCertDir);
        MSCRYPTP_defaultCertDir = MSCRYPT_strdup(defaultCertDir);
    }
}

const char *MSCRYPTP_get_default_cert_area()
{
    if (MSCRYPTP_defaultCertArea) {
        return MSCRYPTP_defaultCertArea;
    } else {
        const char *rootDir = MSCRYPT_ROOT_DIR;
        if (*rootDir == '\0') {
            return X509_get_default_cert_area();
        } else {
            return MSCRYPT_ROOT_DIR;
        }
    }
}

const char *MSCRYPTP_get_default_cert_dir()
{
    if (MSCRYPTP_defaultCertDir) {
        return MSCRYPTP_defaultCertDir;
    } else {
        const char *rootDir = MSCRYPT_ROOT_DIR;
        if (*rootDir == '\0') {
            return X509_get_default_cert_dir();
        } else {
            return MSCRYPT_CERTS_DIR;
        }
    }
}

const char *MSCRYPTP_get_install_image_dir()
{
    const char *dir = MSCRYPT_INSTALL_IMAGE_DIR;
    if (*dir == '\0') {
        return X509_get_default_cert_dir();
    } else {
        return MSCRYPT_INSTALL_IMAGE_DIR;
    }
}


//
// MSCRYPT_ file support functions
//


// Returns BIO_s_mem().
// Ensures a NULL terminator is always appended to the read file contents.
BIO *MSCRYPTP_read_file_string(
    const uuid_t correlationId,
    const char *fileName,
    int disableTraceLog,
    char **str)
{
    const char *title = MSCRYPTP_SUPPORT_TITLE;
    int ret = 0;
    BIO *in = NULL;
    BIO *mem = NULL;
    char buff[512];

    ERR_clear_error();

    in = BIO_new_file(fileName, "rb");
    if (in == NULL) {
        if (!disableTraceLog) {
            MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, "BIO_new_file",
                "file: %s", fileName);
        }
        goto end;
    }

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        goto memErr;
    }

    for (;;) {
        int inl = BIO_read(in, buff, sizeof(buff));

        if (inl <= 0) {
            break;
        }
        if (BIO_write(mem, buff, inl) != inl) {
            goto memErr;
        }
    }

    // Ensure output string is NULL terminated
    buff[0] = '\0';
    if (BIO_write(mem, buff, 1) != 1) {
        goto memErr;
    }

    if (BIO_get_mem_data(mem, str) < 1 || *str == NULL) {
        goto memErr;
    }

    ret = 1;
end:
    if (!ret) {
        BIO_free(mem);
        mem = NULL;
        *str = NULL;
    }

    BIO_free(in);
    return mem;

memErr:
    if (!disableTraceLog) {
        MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, "mem");
    }
    goto end;
}

// Returns number of decode bytes. For a decode error returns -1.
int MSCRYPTP_base64_decode(
    const uuid_t correlationId,
    const char *str,
    unsigned char **bytes)      // MSCRYPT_free()
{
    const char *title = MSCRYPTP_SUPPORT_TITLE;
    int length = -1;
    int strLength = (int) strlen(str);
    int allocLength = 0;

    *bytes = NULL;

    if (strLength % 4 != 0 || strLength / 4 == 0) {
        MSCRYPTP_trace_log_error_para(correlationId, 0, title, "LengthCheck", "Invalid length",
            "length: %d", strLength);
        goto end;
    }

    allocLength = (strLength / 4) * 3;
    *bytes = (unsigned char *) MSCRYPT_zalloc(allocLength);
    if (*bytes == NULL) {
        goto end;
    }

    length = EVP_DecodeBlock(*bytes, str, strLength);
    if (length != allocLength) {
        MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, "EVP_DecodeBlock",
            "length: %d expected: %d", length, allocLength);

        MSCRYPT_free(*bytes);
        *bytes = NULL;
        length = -1;
        goto end;
    }

    // Check for trailing zero bytes: "xxx=" "xx=="
    if (str[strLength - 1] == '=') {
        length--;
        if (str[strLength - 2] == '=') {
            length--;
        }
    }

end:
    return length;
}

// Converts binary bytes to NULL terminated ascii hex characters.
// Returned hex needs (len * 2 + 1) characters
void MSCRYPTP_bytes_to_hex(
    int len,
    const unsigned char *pb,
    char *hex)
{
    for (int i = 0; i < len; i++) {
        int b = (*pb & 0xF0) >> 4;
        *hex++ = (char) ((b <= 9) ? b + L'0' : (b - 10) + L'a');
        b = *pb & 0x0F;
        *hex++ = (char) ((b <= 9) ? b + L'0' : (b - 10) + L'a');
        pb++;
    }
    *hex++ = 0;
}

//
// MSCRYPTP_trace_log_* functions
// 

int MSCRYPTP_traceLogTest = 0;
int MSCRYPTP_traceLogVerbose = 0;
static char *MSCRYPTP_traceLogFilename = NULL;

void MSCRYPTP_set_trace_log_filename(
    const char *filename)
{
    MSCRYPT_free(MSCRYPTP_traceLogFilename);
    MSCRYPTP_traceLogFilename = MSCRYPT_strdup(filename);
}

static FILE *_open_trace_log_filename()
{
    FILE *fp = stdout;

    if (MSCRYPTP_traceLogFilename != NULL) {
        fp = fopen(MSCRYPTP_traceLogFilename, "a");
        if (fp == NULL) {
            fp = stdout;
        }
    }

    return fp;
}

static void _close_trace_log_filename(
    FILE *fp)
{
    if (fp != stdout) {
        fflush(fp);
        fclose(fp);
    }
}


#if 1
typedef enum {
    LogLevel_Debug,
    LogLevel_Info,
    LogLevel_Status,
    LogLevel_Warning,
    LogLevel_Error,
    LogLevel_Assert,
    LogLevel_Event
} LogLevel;
#endif


#define MSCRYPTP_CORRELATION_ID_PREFIX   "correlationId: "

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
    va_list paraArgs)
{
    char paraBuf[MSCRYPTP_TRACELOG_PARA_LENGTH];
#ifdef MSCRYPT_TEST_WINDOWS
    char idBuf[sizeof(uuid_t) * 2 + 1];
#else
    char idBuf[UUID_STR_LEN];
#endif
    LogLevel logLevel = LogLevel_Info;
    int priority = LOG_INFO;
    const char *priorityStr = " info";
    const char *description = "";
    char *descriptionAlloc = NULL;               // MSCryptFree()
    size_t descriptionLength = 0;
    const char *shortFilename = "";

    if ((flags & MSCRYPTP_TRACELOG_VERBOSE_FLAG) != 0 &&
            !MSCRYPTP_traceLogVerbose) {
        return;
    }

    if (file == NULL) {
        file = "";
    }

    if (func == NULL) {
        func = "";
    }

    if (title == NULL) {
        title = "";
    }

    if (loc == NULL) {
        loc = "";
    }

    if (error == NULL) {
        error = "";
    }

    if (paraFormat == NULL) {
        paraFormat = "";
    }

    if (*error != '\0') {
        if (flags & MSCRYPTP_TRACELOG_WARNING_FLAG) {
            logLevel = LogLevel_Warning;
            priority = LOG_WARNING;
            priorityStr = " warn";
        } else {
            logLevel = LogLevel_Error;
            priority = LOG_ERR;
            priorityStr = "error";
        }
    } else if (flags & MSCRYPTP_TRACELOG_VERBOSE_FLAG) {
        priority = LOG_DEBUG;
        priorityStr = "debug";
    }

    if (*loc == '\0') {
        loc = func;
    }

    if (correlationId != NULL) {
#ifdef MSCRYPT_TEST_WINDOWS
        MSCRYPTP_bytes_to_hex(sizeof(uuid_t), correlationId, idBuf);
#else
        uuid_unparse_lower(correlationId, idBuf);
#endif
    } else {
        idBuf[0] = '\0';
    }

    if (vsnprintf(paraBuf, sizeof(paraBuf), paraFormat, paraArgs) < 0) {
        *paraBuf = '\0';
    }

    // Description. Where para, error and correlationId are optional
    //  <loc>":: "<para>" "<error>" ""correlationId: "<correlationId>

    descriptionLength =
        strlen(loc) + 3 +
        strlen(paraBuf) + 1 +
        strlen(error) + 1 +
        strlen(MSCRYPTP_CORRELATION_ID_PREFIX) + strlen(idBuf) + 1;

    descriptionAlloc = (char *) MSCRYPT_zalloc(descriptionLength);
    if (descriptionAlloc != NULL) {
        if (snprintf(descriptionAlloc, descriptionLength,
                "%s:: %s%s%s%s%s%s",
                loc,
                paraBuf, *paraBuf == '\0' ? "" : " ",
                error, *error == '\0' ? "" : " ",
                correlationId == NULL ? "" : MSCRYPTP_CORRELATION_ID_PREFIX,
                correlationId == NULL ? "" : idBuf) > 0) {
            description = descriptionAlloc;
        }
    }

#if 0
    APSDK_DEFINE_CUSTOM_LOGID(MsCrypt);
    Log2(file, func, line, LogID_MsCrypt, logLevel, title, description);
#endif

    // Extract the rightmost filename component. Address Windows and Linux.
    shortFilename = file;
    for (int i = 0; i <= 1; i++) {
        const char *p = strrchr(file, i == 0 ? '/' : '\\');

        if (p != NULL) {
            p++;
            if (*p != '\0' && p > shortFilename) {
                shortFilename = p;
            }
        }
    }

#ifndef MSCRYPT_TEST_WINDOWS
    // "["<prio>"] "<title>" "<func>" "<file>"("<line>") "<description>
    syslog(priority, "[%s] %s %s %s(%d) %s",
           priorityStr, title, func, shortFilename, line, description);
#endif

    if (MSCRYPTP_traceLogTest) {
        struct timeval tv;
        int sec = 0;
        int usec_100 = 0;
        FILE *fp = NULL;
        const char *logLevelStr = "???";

        switch (logLevel) {
            case LogLevel_Info:
                logLevelStr = "Info";
                break;
            case LogLevel_Warning:
                logLevelStr = "Warn";
                break;
            case LogLevel_Error:
                logLevelStr = "Error ";
                break;
        }

        tv.tv_sec = 0;
        tv.tv_usec = 0;
        if (gettimeofday(&tv, NULL) == 0) {
            sec = tv.tv_sec % 100000;
            usec_100 = tv.tv_usec / 100;
        }

        fp = _open_trace_log_filename();
        // <time>" - "<logLevel>" "<title>" "<func>" "<file>"("<line>") "<description>
        fprintf(fp, "%05d.%04d - %s %s %s %s(%d) %s\n",
            sec, usec_100, logLevelStr, title, func, shortFilename, line, description);
        _close_trace_log_filename(fp);
    }


    MSCRYPT_free(descriptionAlloc);
}

void _MSCRYPTP_trace_log_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *format, ...)
{
    va_list args;
    va_start(args, format);

    _MSCRYPTP_trace_log_output(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        "",                         // error
        format,
        args);
}

void _MSCRYPTP_trace_log(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc)
{
    _MSCRYPTP_trace_log_para(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        "");
}

void _MSCRYPTP_trace_log_error_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *errStr,
    const char *format, ...)
{
    va_list args;
    va_start(args, format);
    char errorBuf[MSCRYPTP_TRACELOG_ERROR_LENGTH];
    const char *error = "error: ???";

    if (errStr == NULL) {
        errStr = "";
    }

    if (*errStr != '\0') {
        if (snprintf(errorBuf, sizeof(errorBuf), "error: <%s>", errStr) > 0) {
            error = errorBuf;
        }
    }
    
    _MSCRYPTP_trace_log_output(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        error,
        format,
        args);
}

void _MSCRYPTP_trace_log_error(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *errStr)
{
    _MSCRYPTP_trace_log_error_para(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        errStr,
        "");
}

void _MSCRYPTP_trace_log_openssl_error_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *format, ...)
{
    unsigned long lastErr = ERR_peek_last_error();
    va_list args;
    va_start(args, format);
    char errorBuf[MSCRYPTP_TRACELOG_ERROR_LENGTH];
    const char *error = "error: ???";

    if (snprintf(errorBuf, sizeof(errorBuf), "openSslError: %08lX", lastErr) > 0) {
        error = errorBuf;
    }

    _MSCRYPTP_trace_log_output(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        error,
        format,
        args);

    for (int i = 0; i < 10; i++) {
        char errBuf[128];
        unsigned long err = ERR_get_error();
        if (err == 0) {
            break;
        }

        errBuf[0] = '\0';
        ERR_error_string_n(err, errBuf, sizeof(errBuf));
        errBuf[sizeof(errBuf) - 1] = '\0';

        if (snprintf(errorBuf, sizeof(errorBuf), "openSslError[%d]: <%s>", i, errBuf) > 0) {
            _MSCRYPTP_trace_log_output(
                file,
                func,
                line,
                correlationId,
                flags,
                MSCRYPTP_ERROR_STACK_TITLE,
                loc,
                errorBuf,
                "",                     // format
                args);
        }
    }

    ERR_clear_error();
}

void _MSCRYPTP_trace_log_openssl_error(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc)
{
    _MSCRYPTP_trace_log_openssl_error_para(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        "");                    // format
}

void _MSCRYPTP_trace_log_openssl_verify_cert_error_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    int err,
    const char *format, ...)
{
    va_list args;
    va_start(args, format);
    char errorBuf[MSCRYPTP_TRACELOG_ERROR_LENGTH];
    const char *error = "error: ???";

    if (snprintf(errorBuf, sizeof(errorBuf),
            "verifyCertError: %d <%s>",
            err,
            X509_verify_cert_error_string(err)) > 0) {
        error = errorBuf;
    }

    _MSCRYPTP_trace_log_output(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        error,
        format,
        args);
}

void _MSCRYPTP_trace_log_openssl_verify_cert_error(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    int err)
{
    _MSCRYPTP_trace_log_openssl_verify_cert_error_para(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        err,
        "");                    // format
}

void _MSCRYPTP_trace_log_errno_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    int err,
    const char *format, ...)
{
    va_list args;
    va_start(args, format);
    char errorBuf[MSCRYPTP_TRACELOG_ERROR_LENGTH];
    const char *error = "error: ???";

    if (snprintf(errorBuf, sizeof(errorBuf),
            "errno: %d (0x%x) <%s>",
            err,
            err,
            strerror(err)) > 0) {
        error = errorBuf;
    }

    _MSCRYPTP_trace_log_output(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        error,
        format,
        args);
}

void _MSCRYPTP_trace_log_errno(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    int err)
{
    _MSCRYPTP_trace_log_errno_para(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        err,
        "");                    // format
}


EVP_PKEY *MSCRYPT_load_engine_private_key(
    const uuid_t correlationId,
    const char *engineName,
    const char *engineKeyId)
{
    const char *title = MSCRYPTP_ENGINE_TITLE;
    const char *loc = "";
    EVP_PKEY *pkey = NULL;
    ENGINE *e = NULL;
    int engineInit = 0;

    ERR_clear_error();

    // Following is needed to load the "dynamic" engine, that will load our engine
    ENGINE_load_dynamic();
    e = ENGINE_by_id(engineName);
    if (e == NULL) {
        loc = "ENGINE_by_id";
        goto openSslErr;
    }

    if (!(ENGINE_init(e))){
        loc = "ENGINE_init";
        goto openSslErr;
    }

    engineInit = 1;

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
    if (e != NULL) {
        if (engineInit) {
            ENGINE_finish(e);   // for ENGINE_init()
        }
        ENGINE_free(e);     // for ENGINE_by_id()
    }
    return pkey;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}
