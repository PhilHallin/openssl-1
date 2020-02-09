#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include "mscryptctl.h"
#include "mscryptp.h"
#ifndef MSCRYPT_TEST_WINDOWS
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <glib.h>

G_LOCK_DEFINE_STATIC(MSCRYPTP_disallowedCtlLock);
#endif

static int MSCRYPT_CTL_Subject_cmp(const MSCRYPT_CTL_SUBJECT *const *a,
                                const MSCRYPT_CTL_SUBJECT *const *b)
{
    return (ASN1_STRING_cmp((ASN1_STRING *)&(*a)->subjectIdentifier,
                            (ASN1_STRING *)&(*b)->subjectIdentifier));
}

static int ctl_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                      void *exarg)
{
    MSCRYPT_CTL *a = (MSCRYPT_CTL *)*pval;

    if (!a || !a->subjects)
        return 1;
    switch (operation) {
    case ASN1_OP_D2I_POST:
        (void)sk_MSCRYPT_CTL_SUBJECT_set_cmp_func(a->subjects, MSCRYPT_CTL_Subject_cmp);
        sk_MSCRYPT_CTL_SUBJECT_sort(a->subjects);
        break;
    }
    return 1;
}

ASN1_SEQUENCE(MSCRYPT_CTL_SUBJECT) = {
        ASN1_EMBED(MSCRYPT_CTL_SUBJECT, subjectIdentifier, ASN1_OCTET_STRING),
        ASN1_SET_OF_OPT(MSCRYPT_CTL_SUBJECT, attributes, X509_ATTRIBUTE)
} ASN1_SEQUENCE_END(MSCRYPT_CTL_SUBJECT)

ASN1_SEQUENCE_cb(MSCRYPT_CTL, ctl_cb) = {
        ASN1_OPT(MSCRYPT_CTL, version, ASN1_INTEGER),
        ASN1_SEQUENCE_OF(MSCRYPT_CTL, subjectUsages, ASN1_OBJECT),
        ASN1_OPT(MSCRYPT_CTL, listIdentifier, ASN1_OCTET_STRING),
        ASN1_OPT(MSCRYPT_CTL, sequenceNumber, ASN1_INTEGER),
        ASN1_SIMPLE(MSCRYPT_CTL, thisUpdate, ASN1_TIME),
        ASN1_OPT(MSCRYPT_CTL, nextUpdate, ASN1_TIME),
        ASN1_EMBED(MSCRYPT_CTL, subjectAlgorithm, X509_ALGOR),
        ASN1_SEQUENCE_OF_OPT(MSCRYPT_CTL, subjects, MSCRYPT_CTL_SUBJECT),
        ASN1_EXP_SEQUENCE_OF_OPT(MSCRYPT_CTL, extensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END_cb(MSCRYPT_CTL, MSCRYPT_CTL)

IMPLEMENT_ASN1_FUNCTIONS(MSCRYPT_CTL_SUBJECT)
IMPLEMENT_ASN1_DUP_FUNCTION(MSCRYPT_CTL_SUBJECT)
IMPLEMENT_ASN1_FUNCTIONS(MSCRYPT_CTL)

static MSCRYPT_CTL *d2i_MSCRYPT_CTL_bio(BIO *bp, MSCRYPT_CTL **ctl)
{
    return ASN1_d2i_bio_of(MSCRYPT_CTL, MSCRYPT_CTL_new, d2i_MSCRYPT_CTL, bp, ctl);
}

// MSCRYPT_CTL_free() returned CTL
MSCRYPT_CTL *MSCRYPT_CTL_parse(
    const uuid_t correlationId,
    int ctlLength,
    const unsigned char *ctlBytes)
{
    const char *title = MSCRYPTP_PARSE_CTL_TITLE;
    const char *loc = "";
    BIO *bioIn = NULL;
    MSCRYPT_CTL *ctl = NULL;
    PKCS7 *p7 = NULL;
    BIO *bioContents = NULL;

    ERR_clear_error();

    bioIn = BIO_new_mem_buf(ctlBytes, ctlLength);
    if (bioIn == NULL) {
        loc = "BIO_new_mem_buf";
        goto openSslErr;
    }

    p7 = d2i_PKCS7_bio(bioIn, NULL);
    if (p7 == NULL) {
        loc = "d2i_PKCS7_bio";
        goto openSslErr;
    }

    if (OBJ_obj2nid(p7->type) != NID_pkcs7_signed) {
        loc = "NID_pkcs7_signed";
        goto p7Err;
    }

    if (p7->d.ptr == NULL || p7->d.sign == NULL || p7->d.sign->contents == NULL) {
        loc = "SignContents";
        goto p7Err;
    }

    {
        PKCS7 *contents = p7->d.sign->contents;
        ASN1_OBJECT *objtmp = NULL;
        int isCtl = 0;
        int length = 0;
        unsigned char *data = NULL;

        if ((objtmp = OBJ_txt2obj(szOID_CTL, 0)) != NULL) {
            if (OBJ_cmp(objtmp, contents->type) == 0) {
                isCtl = 1;
            }

            ASN1_OBJECT_free(objtmp);
        }

        if (!isCtl) {
            loc = "CtlOID";
            goto p7Err;
        }

        if (contents->d.other) {
            if (contents->d.other->type == V_ASN1_SEQUENCE) {
                length = contents->d.other->value.sequence->length;
                data = contents->d.other->value.sequence->data;
            } else if (contents->d.other->type == V_ASN1_OCTET_STRING) {
                length = contents->d.other->value.octet_string->length;
                data = contents->d.other->value.octet_string->data;
            }
        }

        if (length <= 0 || data == NULL) {
            loc = "CtlContent";
            goto p7Err;
        }

        bioContents = BIO_new_mem_buf(data, length);
        if (bioContents == NULL) {
            loc = "BIO_new_mem_buf";
            goto openSslErr;
        }
    }

    ctl = d2i_MSCRYPT_CTL_bio(bioContents, NULL);
    if (ctl == NULL) {
        loc = "d2i_MSCRYPT_CTL_bio";
        goto openSslErr;
    }

    ERR_clear_error();
end:
    PKCS7_free(p7);
    BIO_free(bioIn);
    BIO_free(bioContents);

    return ctl;

p7Err:
    MSCRYPTP_trace_log_error(correlationId, 0, title, loc, "PKCS#7 parse error");
    goto end;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

static int _is_disallowed_ctl(
    const uuid_t correlationId,
    const char *title,
    MSCRYPT_CTL *ctl)
{
    const char *loc = "";
    int isDisallowed = 0;

    if (ctl->listIdentifier == NULL || ctl->listIdentifier->length <= 0) {
        loc = "listIdentifier";
        goto notCtl;
    }

    if (ctl->sequenceNumber == NULL || ctl->sequenceNumber->length <= 0) {
        loc = "sequenceNumber";
        goto notCtl;
    }

    if (ctl->thisUpdate == NULL) {
        loc = "thisUpdate";
        goto notCtl;
    }

    {
        ASN1_OBJECT *objtmp = NULL;

        if (sk_ASN1_OBJECT_num(ctl->subjectUsages) == 1) {
            if ((objtmp = OBJ_txt2obj(szOID_DISALLOWED_LIST, 0)) != NULL) {
                if (OBJ_cmp(objtmp, sk_ASN1_OBJECT_value(ctl->subjectUsages, 0)) == 0) {
                    isDisallowed = 1;
                }

                ASN1_OBJECT_free(objtmp);
            }
        }

        if (!isDisallowed) {
            loc = "subjectUsages";
            goto notCtl;
        }
    }

    isDisallowed = 0;
    {
        ASN1_OBJECT *objtmp = NULL;

        if ((objtmp = OBJ_txt2obj(szOID_DISALLOWED_HASH, 0)) != NULL) {
            const ASN1_OBJECT *aoid;
            int aparamtype;
            const void *aparam;

            X509_ALGOR_get0(&aoid, &aparamtype, &aparam, &ctl->subjectAlgorithm);
            if (OBJ_cmp(objtmp, aoid) == 0) {
                isDisallowed = 1;
            }

            ASN1_OBJECT_free(objtmp);
        }

        if (!isDisallowed) {
            loc = "subjectAlgorithm";
            goto notCtl;
        }
    }

    isDisallowed = 1;

end:
    return isDisallowed;

notCtl:
    MSCRYPTP_trace_log_error(correlationId, 0, title, loc, "Not disallowed");
    goto end;
}

static char *_little_endian_uni2asc(const unsigned char *uni, int unilen)
{
    int asclen, i;
    char *asctmp;
    /* string must contain an even number of bytes */
    if (unilen & 1) {
        return NULL;
    }
    asclen = unilen / 2;

    asctmp = MSCRYPT_zalloc(asclen + 1);
    if (asctmp == NULL) {
        return NULL;
    }

    for (i = 0; i < asclen; i++) {
        asctmp[i] = uni[i * 2];
    }

    return asctmp;
}

static char *_format_ctl_name(
    const uuid_t correlationId,
    const char *title,
    MSCRYPT_CTL *ctl)
{
    const char *loc = "";
    BIO *out = NULL;
    const char nullTerminator = '\0';
    char *ctlName = NULL;

    out = BIO_new(BIO_s_mem());
    if (out == NULL) {
        return NULL;
    }

    BIO_printf(out, "listIdentifier=");
    if (ctl->listIdentifier) {
        char *ascIdentifier = _little_endian_uni2asc(ctl->listIdentifier->data, ctl->listIdentifier->length);
        
        for (int i = 0; i < ctl->listIdentifier->length; i++) {
            BIO_printf(out, "%02x", ctl->listIdentifier->data[i]);
        }

        if (ascIdentifier != NULL) {
            BIO_printf(out, " <%s>", ascIdentifier);
            MSCRYPT_free(ascIdentifier);
        }
    }

    BIO_printf(out, ",sequenceNumber=");
    if (ctl->sequenceNumber) {
        for (int i = 0; i < ctl->sequenceNumber->length; i++) {
            BIO_printf(out, "%02x", ctl->sequenceNumber->data[i]);
        }
    }

    BIO_printf(out, ",thisUpdate=<");
    if (ctl->thisUpdate) {
        ASN1_TIME_print(out, ctl->thisUpdate);
    }
    BIO_printf(out, ">");


    {
        const char *name = NULL;
        int nameLength = (int) BIO_get_mem_data(out, &name);

        if (nameLength > 0 && name != NULL) {
            ctlName = (char *) MSCRYPT_zalloc(nameLength + 1);
            if (ctlName != NULL) {
                memcpy(ctlName, name, nameLength);
            }
        }
    }
            
    BIO_free(out);
    return ctlName;
}

// MSCRYPT_free() returned name
char *MSCRYPT_CTL_format_name(
    const uuid_t correlationId,
    MSCRYPT_CTL *ctl)
{
    return _format_ctl_name(correlationId, MSCRYPTP_ENUM_DISALLOWED_CTL_TITLE, ctl);
}

static int _list_identifier_filename_hex_hash(
    const uuid_t correlationId,
    const char *title,
    ASN1_OCTET_STRING *listIdentifier,
    char *hexHash)
{
    const char *loc = "";
    int ret = 0;
    unsigned char md[SHA256_DIGEST_LENGTH];
    int fileHashLen;

    ERR_clear_error();

    if (!EVP_Digest(listIdentifier->data, listIdentifier->length, md, NULL, EVP_sha256(), NULL)) {
        loc = "EVP_Digest";
        goto openSslErr;
    }

    fileHashLen = sizeof(md);
    if (fileHashLen > MSCRYPTP_MAX_FILENAME_HASH_LENGTH) {
        fileHashLen = MSCRYPTP_MAX_FILENAME_HASH_LENGTH;
    }

    MSCRYPTP_bytes_to_hex(
        fileHashLen,
        md,
        hexHash);
    ret = 1;

end:
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

// MSCRYPT_free() returned path name
static char *_get_disallowed_ctl_path_name(
    const char *subPath) // optional
{
    const char *openSslDir = MSCRYPTP_get_default_cert_area();
    size_t openSslDirLength = strlen(openSslDir);
    const char *subDir = "disallowed/ctl";
    size_t subDirLength = strlen(subDir);
    size_t subPathLength = (subPath != NULL && subPath[0] != '\0') ? strlen(subPath) : 0;
    size_t disallowedPathLength = openSslDirLength + 1 + subDirLength + 1 + subPathLength + 1;
    char *disallowedPath = (char *) MSCRYPT_zalloc(disallowedPathLength);

    if (disallowedPath != NULL) {
        if (subPathLength == 0) {
            BIO_snprintf(disallowedPath, disallowedPathLength, "%s/%s",
                openSslDir, subDir);
        } else {
            BIO_snprintf(disallowedPath, disallowedPathLength, "%s/%s/%s",
                openSslDir, subDir, subPath);
        }
    }

    return disallowedPath;
}

#ifdef MSCRYPT_TEST_WINDOWS
static int _mkdir(
    const uuid_t correlationId,
    const char *title,
    const char *dir)
{
    return 1;
}
#else
static int _mkdir(
    const uuid_t correlationId,
    const char *title,
    const char *dir)
{
    int ret = 0;

    if (mkdir(dir, 0755) == 0) {
        ret = 1;
    } else {
        int err = errno;
        if (err == EEXIST) {
            ret = 1;
        } else {
            MSCRYPTP_trace_log_errno_para(correlationId, 0, title, "mkdir", err,
                "dir: %s", dir);
        }
    }

    return ret;
}
#endif

#define MSCRYPTP_CTL_COUNTER_FILENAME   "counter"

#ifdef MSCRYPT_TEST_WINDOWS
static int _update_disallowed_ctl_counter_file(
    const uuid_t correlationId,
    const char *title)
{
    return 1;
}

static int _read_disallowed_ctl_counter_file(
    const uuid_t correlationId,
    const char *title)
{
    static unsigned int counter = 0;

    return ++counter;
}

#else

static int _update_disallowed_ctl_counter_file(
    const uuid_t correlationId,
    const char *title)
{
    int ret = 0;
    const char *loc = "";
    char *counterPath  = NULL;      // MSCRYPT_free(); 
    int fd = -1;
    ssize_t numBytes = 0;
    unsigned int counter = 0;

    counterPath = _get_disallowed_ctl_path_name(MSCRYPTP_CTL_COUNTER_FILENAME);
    if (counterPath == NULL) {
        goto end;
    }

    fd = open(counterPath, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd == -1) {
        loc = "open";
        goto errnoErr;
    }

    numBytes = read(fd, &counter, sizeof(counter));
    if (numBytes != sizeof(counter)) {
        counter = 0;
    }
    counter++;

    lseek(fd, 0, SEEK_SET);
    numBytes = write(fd, &counter, sizeof(counter));
    if (numBytes != sizeof(counter)) {
        loc = "write";
        goto errnoErr;
    }

    ret = 1;

end:
    MSCRYPT_free(counterPath);
    if (fd != -1) {
        close(fd);
    }

    return ret;

errnoErr:
    {
        int err = errno;
        MSCRYPTP_trace_log_errno_para(correlationId, 0, title, loc, err,
            "filename: %s", counterPath);
    }
    goto end;
}


static unsigned int _read_disallowed_ctl_counter_file(
    const uuid_t correlationId,
    const char *title)
{
    unsigned int counter = 0;
    const char *loc = "";
    char *counterPath  = NULL;      // MSCRYPT_free(); 
    int fd = -1;
    ssize_t numBytes = 0;

    counterPath = _get_disallowed_ctl_path_name(MSCRYPTP_CTL_COUNTER_FILENAME);
    if (counterPath == NULL) {
        goto end;
    }

    fd = open(counterPath, O_RDONLY, 0);
    if (fd == -1) {
        loc = "open";
        goto errnoErr;
    }

    numBytes = read(fd, &counter, sizeof(counter));
    if (numBytes != sizeof(counter)) {
        counter = 0;
        loc = "read";
        goto errnoErr;
    }

end:
    MSCRYPT_free(counterPath);
    if (fd != -1) {
        close(fd);
    }

    return counter;

errnoErr:
    {
        int err = errno;
        if (err != ENOENT) {
            MSCRYPTP_trace_log_errno_para(correlationId, 0, title, loc, err,
                "filename: %s", counterPath);
        }
    }
    goto end;
}

#endif


int MSCRYPT_SERVER_ctl_ctrl(
    const uuid_t correlationId,
    int ctrl,
    int location,
    int length,
    const unsigned char *bytes)
{
    const char *title = MSCRYPTP_get_ctl_ctrl_title(ctrl, location);
    const char *loc = "";
    int ret = 0;
    int noUpdateRet = 0;
    MSCRYPT_CTL *inCtl = NULL;
    char *allocCtlName = NULL;                  // MSCRYPT_free()
    const char *ctlName = "";

    BIO *bioFile = NULL;
    BIO *memFile = NULL;
    BIO *bioExists = NULL;
    int existsLength = 0;
    const unsigned char *existsBytes = NULL;    // Don't free
    MSCRYPT_CTL *existsCtl = NULL;

    char filenameHexHash[MSCRYPTP_MAX_FILENAME_HEX_HASH_LENGTH];
    char *disallowedCtlDirName = NULL;          // MSCRYPT_free()
    int filenameLength = 0;
    char *filename = NULL;                      // MSCRYPT_free()
    int tmpFilenameLength = 0;
    char *tmpFilename = NULL;                   // MSCRYPT_free()
    char *outFilename = NULL;                   // Don't free
    BIO *bioOut = NULL;

    ERR_clear_error();

    if (location != MSCRYPT_CERT_LOCATION_DISALLOWED ||
        !(ctrl == MSCRYPT_CERT_CTRL_IMPORT || ctrl == MSCRYPT_CERT_CTRL_REMOVE)) {
        MSCRYPTP_trace_log_error(correlationId, 0, title, "location or ctrl", "Not supported");
        goto end;
    }

    inCtl = MSCRYPT_CTL_parse(correlationId, length, bytes);
    if (inCtl == NULL) {
        goto end;
    }

    if (!_is_disallowed_ctl(correlationId, title, inCtl)) {
        goto end;
    }

    allocCtlName = _format_ctl_name(correlationId, title, inCtl);
    if (allocCtlName != NULL) {
        ctlName = allocCtlName;
    }

    if (!_list_identifier_filename_hex_hash(correlationId, title, inCtl->listIdentifier, filenameHexHash)) {
        goto end;
    }

    disallowedCtlDirName = _get_disallowed_ctl_path_name("");
    if (disallowedCtlDirName == NULL) {
        loc = "_get_disallowed_ctl_path_name";
        goto openSslErr;
    }

    if (!_mkdir(correlationId, title, disallowedCtlDirName)) {
        goto end;
    }

    // Here is an example disallowed ctl filename
    // "C:\Program Files\Common Files\SSL/disallowed/ctl/feb4772a68567e28a9186ac179fdbf6a.ctl"
    // "C:\Program Files\Common Files\SSL/disallowed/ctl" /" "feb4772a68567e28a9186ac179fdbf6a" ".ctl" "\0"
    //                                                    0   01234567890123456789012345678901   0123   0
    //                                                                  1         2         3 

    filenameLength = (int) strlen(disallowedCtlDirName) + 1 + (int) strlen(filenameHexHash) + 4 + 1;
    filename = (char *) MSCRYPT_zalloc(filenameLength);
    if (filename == NULL) {
        goto end;
    }

    BIO_snprintf(filename, filenameLength, "%s/%s.ctl", disallowedCtlDirName, filenameHexHash);

    bioFile = BIO_new_file(filename, "rb");
    if (bioFile == NULL) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != BIO_R_NO_SUCH_FILE) {
            MSCRYPTP_trace_log_openssl_error_para(correlationId,
                MSCRYPTP_TRACELOG_WARNING_FLAG, title, "BIO_new_file",
                "ctlName: %s filename: %s", ctlName, filename);
        }

        if (ctrl == MSCRYPT_CERT_CTRL_REMOVE) {
            MSCRYPTP_trace_log_error_para(correlationId,
                MSCRYPTP_TRACELOG_VERBOSE_FLAG | MSCRYPTP_TRACELOG_WARNING_FLAG,
                title, "Remove", "Ctl already removed",
                "ctlName: %s filenameHexHash: %s", ctlName, filenameHexHash);
            noUpdateRet = 1;
            ret = 1;
            goto end;
        }
    } else if (ctrl == MSCRYPT_CERT_CTRL_REMOVE) {
        BIO_free(bioFile);
        bioFile = NULL;

        if (remove(filename) == 0) {
            MSCRYPTP_trace_log_para(correlationId, 0, title, "Remove",
                "ctlName: %s filename: %s", ctlName, filename);
            ret = 1;
        } else {
            int err = errno;
            MSCRYPTP_trace_log_errno_para(correlationId, 0, title, "Remove", err,
                "ctlName: %s filename: %s", ctlName, filename);
        }
        goto end;
    } else {
        memFile = BIO_new(BIO_s_mem());
        if (memFile == NULL) {
            loc = "BIO_new";
            goto openSslErr;
        }

        for (;;) {
            char buff[512];
            int inl = BIO_read(bioFile, buff, sizeof(buff));

            if (inl <= 0) 
                break;
            if (BIO_write(memFile, buff, inl) != inl) {
                loc = "BIO_write";
                goto openSslErr;
            }
        }

        existsLength = (int) BIO_get_mem_data(memFile, (char **) &existsBytes);

        if (existsLength == length && 0 == memcmp(bytes, existsBytes, length)) {
            MSCRYPTP_trace_log_error_para(correlationId,
                MSCRYPTP_TRACELOG_VERBOSE_FLAG | MSCRYPTP_TRACELOG_WARNING_FLAG,
                title, "Import", "Already exists",
                "ctlName: %s filename: %s", ctlName, filename);
            noUpdateRet = 1;
            ret = 1;
            goto end;
        }

        existsCtl = MSCRYPT_CTL_parse(correlationId, existsLength, existsBytes);
        if (existsCtl != NULL) {
            if (_is_disallowed_ctl(correlationId, title, existsCtl)) {
                int isNewer = 0;
                const char *existsCtlName = "";
                char *existsAllocCtlName = NULL;    // MSCRYPT_free()

                existsAllocCtlName = _format_ctl_name(correlationId, title, existsCtl);
                if (existsAllocCtlName != NULL) {
                    existsCtlName = existsAllocCtlName;
                }

                if (inCtl->sequenceNumber->length > existsCtl->sequenceNumber->length) {
                    isNewer = 1;
                } else if (inCtl->sequenceNumber->length == existsCtl->sequenceNumber->length &&
                    0 <= memcmp(inCtl->sequenceNumber->data,
                                existsCtl->sequenceNumber->data,
                                inCtl->sequenceNumber->length)) {
                    isNewer = 1;
                }

                if (isNewer) {
                    MSCRYPTP_trace_log_para(correlationId, 0, title,
                        "Import Newer",
                        "ctlName: %s filename: %s", ctlName, filename);
                    MSCRYPTP_trace_log_para(correlationId, 0, title,
                        "Existing",
                        "ctlName: %s", existsCtlName);
                } else {
                    MSCRYPTP_trace_log_error_para(correlationId, MSCRYPTP_TRACELOG_WARNING_FLAG, title,
                        "Import", "Replacing with older",
                        "ctlName: %s filename: %s", ctlName, filename);
                    MSCRYPTP_trace_log_error_para(correlationId, MSCRYPTP_TRACELOG_WARNING_FLAG, title,
                        "Existing", "Is newer",
                        "ctlName: %s", existsCtlName);
                }

                MSCRYPT_free(existsAllocCtlName);
            }
        }
    }


    if (bioFile == NULL) {
        outFilename = filename;
    } else {
        // filename + ".tmp"
        //             0123
        tmpFilenameLength = filenameLength + 4;
        tmpFilename = (char *) MSCRYPT_zalloc(tmpFilenameLength);
        if (tmpFilename == NULL) {
            goto openSslErr;
        }

        BIO_snprintf(tmpFilename, tmpFilenameLength, "%s.tmp", filename);
        outFilename = tmpFilename;
        MSCRYPTP_trace_log_para(correlationId, MSCRYPTP_TRACELOG_VERBOSE_FLAG, title, "TempCtl",
            "filename: %s", tmpFilename);
    }

    bioOut = BIO_new_file(outFilename, "wb");
    if (bioOut == NULL) {
        MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, "BIO_new_file",
            "ctlName: %s filename: %s", ctlName, outFilename);
        goto end;
    }

    if (BIO_write(bioOut, bytes, length) != length) {
        MSCRYPTP_trace_log_openssl_error_para(correlationId, 0,
            title, "BIO_write",
            "ctlName: %s filename: %s", ctlName, outFilename);
        goto end;
    }
    BIO_flush(bioOut);

    if (tmpFilename) {
        // Ensure the files are closed before rename.
        BIO_free(bioFile);
        bioFile = NULL;

        BIO_free(bioOut);
        bioOut = NULL;

        ret = MSCRYPTP_rename_file(correlationId, title, tmpFilename, filename);
    } else {
        ret = 1;
    }

    if (ret) {
        MSCRYPTP_trace_log_para(correlationId, 0, title, "Import",
            "ctlName: %s filename: %s", ctlName, filename);
    }

end:
    if (noUpdateRet) {
        ;
    } else if (ret) {
        ret = _update_disallowed_ctl_counter_file(correlationId, title);
    }

    MSCRYPT_CTL_free(inCtl);
    MSCRYPT_free(allocCtlName);

    BIO_free(bioFile);
    BIO_free(memFile);
    BIO_free(bioExists);
    MSCRYPT_CTL_free(existsCtl);

    MSCRYPT_free(disallowedCtlDirName);
    MSCRYPT_free(filename);
    MSCRYPT_free(tmpFilename);
    BIO_free(bioOut);

    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

static int _read_disallowed_ctl_file(
    const uuid_t correlationId,
    const char *ctlPath,
    int *ctlLength,
    unsigned char **ctlBytes)   // MSCRYPT_free()
{
    const char *title = MSCRYPTP_ENUM_DISALLOWED_CTL_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *bioFile = NULL;
    BIO *bioMem = NULL;
    int memLength = 0;
    const unsigned char *memBytes;
    MSCRYPT_CTL *ctl = NULL;

    *ctlLength = 0;
    *ctlBytes = NULL;

    ERR_clear_error();

    bioFile = BIO_new_file(ctlPath, "rb");
    if (bioFile == NULL) {
        loc = "BIO_new_file";
        goto openSslErr;
    }

    bioMem = BIO_new(BIO_s_mem());
    if (bioMem == NULL) {
        loc = "BIO_new";
        goto openSslErr;
    }

    for (;;) {
        char buff[512];
        int inl = BIO_read(bioFile, buff, sizeof(buff));

        if (inl <= 0) 
            break;
        if (BIO_write(bioMem, buff, inl) != inl) {
            loc = "BIO_write";
            goto openSslErr;
        }
    }

    memLength = (int) BIO_get_mem_data(bioMem, (char **) &memBytes);
    if (memLength == 0 || memBytes == NULL) {
        loc = "BIO_get_mem_data";
        goto openSslErr;
    }

    ctl = MSCRYPT_CTL_parse(correlationId, memLength, memBytes);
    if (ctl == NULL) {
        loc = "MSCRYPT_CTL_parse";
        goto parseErr;
    }

    if (!_is_disallowed_ctl(correlationId, title, ctl)) {
        loc = "_is_disallowed_ctl";
        goto parseErr;
    }

    *ctlBytes = (char *) MSCRYPT_zalloc(memLength);
    if (*ctlBytes == NULL) {
        goto end;
    }
    memcpy(*ctlBytes, memBytes, memLength);
    *ctlLength = memLength;

    ret = 1;

end:
    BIO_free(bioFile);
    BIO_free(bioMem);
    MSCRYPT_CTL_free(ctl);

    return ret;
openSslErr:
    MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "filename: %s", ctlPath);
    goto end;

parseErr:
    MSCRYPTP_trace_log_error_para(correlationId, 0, title, loc, "Parse Error",
        "filename: %s", ctlPath);
    goto end;
}


#ifdef MSCRYPT_TEST_WINDOWS

#define MSCRYPT_TEST_WINDOWS_MAX_DIR_ITERATION  5
struct MSCRYPT_ctl_dir_st {
    uuid_t          correlationId;
    unsigned int    iteration;    
    char            *dirName;           // MSCRYPT_free()
};

// Returns directory handle or NULL on error.
MSCRYPT_CTL_DIR *MSCRYPT_open_disallowed_ctl_dir(
    const uuid_t correlationId,
    int mscryptFlags)
{
    const char *title = MSCRYPTP_ENUM_DISALLOWED_CTL_TITLE;
    int ret = 0;
    MSCRYPT_CTL_DIR *ctlDir = NULL;           

    ctlDir = (MSCRYPT_CTL_DIR *) MSCRYPT_zalloc(sizeof(*ctlDir));
    if (ctlDir == NULL) {
        goto end;
    }

    if (correlationId == NULL) {
        RAND_bytes(ctlDir->correlationId, sizeof(ctlDir->correlationId));
    } else {
        memcpy(ctlDir->correlationId, correlationId, sizeof(ctlDir->correlationId));
    }

    ctlDir->dirName = _get_disallowed_ctl_path_name(NULL);
    if (ctlDir->dirName == NULL) {
        MSCRYPTP_trace_log_openssl_error(ctlDir->correlationId, 0, title, "_get_disallowed_ctl_dir");
        goto end;
    }

    ret = 1;

end:
    if (!ret) {
        MSCRYPT_close_ctl_dir(ctlDir);
        ctlDir = NULL;
    }
    return ctlDir;
}

// Return:
//  +1 - Success with *ctlLength and *ctlBytes updated
//  -1 - No more ctls. *ctlLength is set to 0 and *ctlBytes is set to NULL.
//   0 - Error
int MSCRYPT_read_ctl_dir(
    MSCRYPT_CTL_DIR *ctlDir,
    int *ctlLength,
    unsigned char **ctlBytes)   // MSCRYPT_free()
{
    const char *title = MSCRYPTP_ENUM_DISALLOWED_CTL_TITLE;
    int ret = 0;
    char *ctlPath = NULL;       // MSCRYPT_free()
    
    *ctlLength = 0;
    *ctlBytes = NULL;

    for (int i = ctlDir->iteration; i < MSCRYPT_TEST_WINDOWS_MAX_DIR_ITERATION; i++) {
        int nameLength = 0;
        int ctlPathLength = 0;
        
        nameLength = (int) strlen("1234.ctl");
        ctlPathLength = (int) strlen(ctlDir->dirName) + 1 + nameLength + 1;
                
        MSCRYPT_free(ctlPath);
        ctlPath = (char *) MSCRYPT_zalloc(ctlPathLength);
        if (ctlPath == NULL) {
            goto end;
        }

        BIO_snprintf(ctlPath, ctlPathLength, "%s/%d.ctl",
            ctlDir->dirName, i);

        ctlDir->iteration = i + 1;
        if (_read_disallowed_ctl_file(
                ctlDir->correlationId,
                ctlPath,
                ctlLength,
                ctlBytes)) {
            ret = 1;
            goto end;
        }

        MSCRYPTP_trace_log_openssl_error_para(ctlDir->correlationId, 0, title, "_read_disallowed_ctl_file",
            "filename: %s", ctlPath);
    }

    ret = -1;

end:
    MSCRYPT_free(ctlPath);

    return ret;
}

void MSCRYPT_close_ctl_dir(
    MSCRYPT_CTL_DIR *ctlDir)
{
    if (ctlDir != NULL) {
        MSCRYPT_free(ctlDir->dirName);
        MSCRYPT_free(ctlDir);
    }
}

#else

struct MSCRYPT_ctl_dir_st {
    uuid_t      correlationId;
    DIR         *dir;               // closedir()
    char        *dirName;           // MSCRYPT_free()
};

// Returns directory handle or NULL on error.
MSCRYPT_CTL_DIR *MSCRYPT_open_disallowed_ctl_dir(
    const uuid_t correlationId,
    int mscryptFlags)
{
    const char *title = MSCRYPTP_ENUM_DISALLOWED_CTL_TITLE;
    int ret = 0;
    MSCRYPT_CTL_DIR *ctlDir = NULL;           

    ERR_clear_error();

    ctlDir = (MSCRYPT_CTL_DIR *) MSCRYPT_zalloc(sizeof(*ctlDir));
    if (ctlDir == NULL) {
        goto end;
    }

    if (correlationId == NULL) {
        RAND_bytes(ctlDir->correlationId, sizeof(ctlDir->correlationId));
    } else {
        memcpy(ctlDir->correlationId, correlationId, sizeof(ctlDir->correlationId));
    }

    ctlDir->dirName = _get_disallowed_ctl_path_name(NULL);
    if (ctlDir->dirName == NULL) {
        MSCRYPTP_trace_log_openssl_error(ctlDir->correlationId, 0, title, "_get_disallowed_ctl_dir");
        goto end;
    }

    ctlDir->dir = opendir(ctlDir->dirName);
    if (ctlDir->dir == NULL) {
        int err = errno;

        if (err != ENOENT) {
            MSCRYPTP_trace_log_errno_para(ctlDir->correlationId, 0, title, "opendir", err,
                "ctlDir: %s", ctlDir->dirName);
        }
        goto end;
    }

    ret = 1;

end:
    if (!ret) {
        MSCRYPT_close_ctl_dir(ctlDir);
        ctlDir = NULL;
    }
    return ctlDir;
}

// Return:
//  +1 - Success with *ctlLength and *ctlBytes updated
//  -1 - No more ctls. *ctlLength is set 0 and *ctlBytes is set to NULL.
//   0 - Error
int MSCRYPT_read_ctl_dir(
    MSCRYPT_CTL_DIR *ctlDir,
    int *ctlLength,
    unsigned char **ctlBytes)   // MSCRYPT_free()
{
    const char *title = MSCRYPTP_ENUM_DISALLOWED_CTL_TITLE;
    int ret = 0;
    const int asciiHexLength = MSCRYPTP_MAX_FILENAME_HASH_LENGTH * 2;
    char *ctlPath = NULL;       // MSCRYPT_free()
    
    *ctlLength = 0;
    *ctlBytes = NULL;

    for(;;) {
        int nameLength = 0;
        int ctlPathLength = 0;
        int validName = 1;
        struct dirent *dp = NULL;

        errno = 0;
        dp = readdir(ctlDir->dir);

        if (dp == NULL) {
            int err = errno;

            if (err == 0) {
                ret = -1;
            } else {
                MSCRYPTP_trace_log_errno_para(ctlDir->correlationId, 0, title, "readdir", err,
                    "ctlDir: %s", ctlDir->dirName);
            }

            break;
        }

        // Skip "." and ".."
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0) {
            continue;
        }

        nameLength = (int) strlen(dp->d_name);
        ctlPathLength = (int) strlen(ctlDir->dirName) + 1 + nameLength + 1;
                
        MSCRYPT_free(ctlPath);
        ctlPath = (char *) MSCRYPT_zalloc(ctlPathLength);
        if (ctlPath == NULL) {
            break;
        }

        BIO_snprintf(ctlPath, ctlPathLength, "%s/%s",
            ctlDir->dirName, dp->d_name);

        // Skip files not matching 
        //  514be7009413c5cd96e99a33dc499f5d.ctl   32 asciiHex ".ctl"  "\0"

        if (nameLength < asciiHexLength + 2 ||
            0 != strcmp(&dp->d_name[asciiHexLength], ".ctl")) {
                validName = 0;
        } else {
            for (int i = 0; i < asciiHexLength; i++) {
                int c = dp->d_name[i];
                if (isdigit(c) || (c >= 'a' && c <= 'f')) {
                    continue;
                }

                validName = 0;
                break;
            }
        }

        if (!validName) {
            MSCRYPTP_trace_log_para(ctlDir->correlationId, MSCRYPTP_TRACELOG_VERBOSE_FLAG, title, "Skipping file",
                "filename: %s", ctlPath);
            continue;
        }

        if (_read_disallowed_ctl_file(
                ctlDir->correlationId,
                ctlPath,
                ctlLength,
                ctlBytes)) {
            ret = 1;
            break;
        }

        MSCRYPTP_trace_log_openssl_error_para(ctlDir->correlationId, 0, title, "_read_disallowed_ctl_file",
            "filename: %s", ctlPath);
    }

    MSCRYPT_free(ctlPath);

    return ret;
}


void MSCRYPT_close_ctl_dir(
    MSCRYPT_CTL_DIR *ctlDir)
{
    if (ctlDir != NULL) {
        if (ctlDir->dir != NULL) {
            closedir(ctlDir->dir);
        }
        MSCRYPT_free(ctlDir->dirName);
        MSCRYPT_free(ctlDir);
    }
}


#endif


struct MSCRYPTP_ctls_ctx_st {
    STACK_OF(MSCRYPT_CTL) *ctls;
    unsigned int refCnt;
};

static MSCRYPTP_CTLS_CTX *MSCRYPTP_currentDisallowedCtlsCtx;
static unsigned int MSCRYPTP_currentDisallowedCtlsCounter;

static void MSCRYPTP_free_ctls_ctx(
    MSCRYPTP_CTLS_CTX *ctx)
{
    if (ctx == NULL) {
        return;
    }

    sk_MSCRYPT_CTL_pop_free(
        ctx->ctls,
        MSCRYPT_CTL_free);

    MSCRYPT_free(ctx);
}


MSCRYPTP_CTLS_CTX *MSCRYPTP_get_disallowed_ctls_ctx(
    const uuid_t correlationId)
{
    const char *title = MSCRYPTP_IS_DISALLOWED_TITLE;
    const char *loc = "";
    MSCRYPTP_CTLS_CTX *newCtx = NULL;   // MSCRYPTP_free_ctls_ctx()
    MSCRYPTP_CTLS_CTX *freeCtx = NULL;  // MSCRYPTP_free_ctls_ctx()
    MSCRYPTP_CTLS_CTX *retCtx = NULL;   // don't free
    MSCRYPT_CTL_DIR *ctlDir = NULL;     // MSCRYPT_close_ctl_dir()
    int ctlLength = 0;
    unsigned char *ctlBytes = 0;        // MSCRYPT_free()
    MSCRYPT_CTL *ctl = NULL;            // MSCRYPT_CTL_free()
    unsigned int counter = 0;

#ifndef MSCRYPT_TEST_WINDOWS
    G_LOCK(MSCRYPTP_disallowedCtlLock);
#endif

    ERR_clear_error();

    counter = _read_disallowed_ctl_counter_file(correlationId, title);

    if (MSCRYPTP_currentDisallowedCtlsCtx != NULL && counter == MSCRYPTP_currentDisallowedCtlsCounter) {
        goto end;
    }

    newCtx = (MSCRYPTP_CTLS_CTX *) MSCRYPT_zalloc(sizeof(MSCRYPTP_CTLS_CTX));
    if (newCtx == NULL) {
        goto end;
    }

    newCtx->refCnt = 1;
    newCtx->ctls = sk_MSCRYPT_CTL_new_null();
    if (newCtx->ctls == NULL) {
        loc = "sk_MSCRYPT_CTL_new_null";
        goto openSslErr;
    }

    ctlDir = MSCRYPT_open_disallowed_ctl_dir(correlationId, 0);
    if (ctlDir == NULL) {
        goto end;
    }

    for (;;) {
        int ret = 0;

        ctlLength = 0;
        MSCRYPT_free(ctlBytes);
        ctlBytes = NULL;

        MSCRYPT_CTL_free(ctl);
        ctl = NULL;

        ret = MSCRYPT_read_ctl_dir(
            ctlDir,
            &ctlLength,
            &ctlBytes);
        if (ret == 0) {
            // Don't update counter for an error
            counter = 0;
        }
        if (ret <= 0) {
            break;
        }

        ctl = MSCRYPT_CTL_parse(correlationId, ctlLength, ctlBytes);
        if (ctl == NULL) {
            loc = "MSCRYPT_CTL_parse";
            goto openSslErr;
        }

        if (!sk_MSCRYPT_CTL_push(newCtx->ctls, ctl)) {
            loc = "sk_MSCRYPT_CTL_push";
            goto openSslErr;
        }
        ctl = NULL;
    }

    if (MSCRYPTP_currentDisallowedCtlsCtx != NULL) {
        if (--MSCRYPTP_currentDisallowedCtlsCtx->refCnt == 0) {
            freeCtx = MSCRYPTP_currentDisallowedCtlsCtx;
        }
    }

    MSCRYPTP_currentDisallowedCtlsCounter = counter;
    MSCRYPTP_currentDisallowedCtlsCtx = newCtx;
    newCtx = NULL;

end:
    if (MSCRYPTP_currentDisallowedCtlsCtx != NULL) {
        retCtx = MSCRYPTP_currentDisallowedCtlsCtx;
        retCtx->refCnt++;
    }

#ifndef MSCRYPT_TEST_WINDOWS
    G_UNLOCK(MSCRYPTP_disallowedCtlLock);
#endif

    MSCRYPTP_free_ctls_ctx(newCtx);
    MSCRYPTP_free_ctls_ctx(freeCtx);
    MSCRYPT_close_ctl_dir(ctlDir);
    MSCRYPT_free(ctlBytes);
    MSCRYPT_CTL_free(ctl);

    return retCtx;
openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

void MSCRYPTP_release_ctls_ctx(
    MSCRYPTP_CTLS_CTX *ctx)
{
    if (ctx == NULL) {
        return;
    }

#ifndef MSCRYPT_TEST_WINDOWS
    G_LOCK(MSCRYPTP_disallowedCtlLock);
#endif

    if (--ctx->refCnt != 0) {
        ctx = NULL;
    }

#ifndef MSCRYPT_TEST_WINDOWS
    G_UNLOCK(MSCRYPTP_disallowedCtlLock);
#endif

    MSCRYPTP_free_ctls_ctx(ctx);
}

int MSCRYPTP_is_cert_hash_in_disallowed_ctls_ctx(
    const uuid_t correlationId,
    MSCRYPTP_CTLS_CTX *ctx,
    unsigned char *md,
    int mdLen)
{
    int isDisallowed = 0;
    const char *title = MSCRYPTP_IS_DISALLOWED_TITLE;
    const char *loc = "";
    MSCRYPT_CTL_SUBJECT findSubject = { 0 };

    if (ctx == NULL || ctx->ctls == NULL) {
        goto end;
    }

    findSubject.subjectIdentifier.type = V_ASN1_OCTET_STRING;
    findSubject.subjectIdentifier.data = md;
    findSubject.subjectIdentifier.length = mdLen;

    for (int i = 0; i < sk_MSCRYPT_CTL_num(ctx->ctls); i++) {
        MSCRYPT_CTL *ctl = sk_MSCRYPT_CTL_value(ctx->ctls, i);

        if (sk_MSCRYPT_CTL_SUBJECT_find(ctl->subjects, &findSubject) >= 0) {
            isDisallowed = 1;

            MSCRYPTP_trace_log_error(correlationId, 0, title,
                "CTL_SUBJECT_find", "Disallowed cert");
            break;
        }
    }

end:
    return isDisallowed;
}
