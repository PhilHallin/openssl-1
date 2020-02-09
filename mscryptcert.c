#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#ifndef MSCRYPT_TEST_WINDOWS
#include <dirent.h>
#endif
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include "mscryptp.h"

#ifndef MSCRYPT_TEST_WINDOWS
#include <glib.h>
G_LOCK_DEFINE_STATIC(MSCRYPT_certCtrlLock);
G_LOCK_DEFINE_STATIC(MSCRYPT_certCtrlDisallowedLock);
#endif

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
    const unsigned char *certBytes)
{
    return MSCRYPT_CLIENT_cert_ctrl(
        correlationId,
        sharedMem,
        MSCRYPT_CERT_CTRL_IMPORT,
        MSCRYPT_CERT_LOCATION_ROOT,
        certFormat,
        certLength,
        certBytes);
}

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
    const unsigned char *certBytes)
{
    return MSCRYPT_CLIENT_cert_ctrl(
        correlationId,
        sharedMem,
        MSCRYPT_CERT_CTRL_REMOVE,
        MSCRYPT_CERT_LOCATION_ROOT,
        certFormat,
        certLength,
        certBytes);
}

// Return:
//  +1 - Success with all certificates imported.
//  -1 - Partial Success. Imported at least one certificate. Failed to
//       import one or more certificates.
//   0 - Error, unable to import any certificates.
int MSCRYPT_import_disallowed_certs(
    const uuid_t correlationId,
    MSCRYPT_SHARED_MEM *sharedMem,  // Optional
    int certFormat,
    int certLength,
    const unsigned char *certBytes)
{
    return MSCRYPT_CLIENT_cert_ctrl(
        correlationId,
        sharedMem,
        MSCRYPT_CERT_CTRL_IMPORT,
        MSCRYPT_CERT_LOCATION_DISALLOWED,
        certFormat,
        certLength,
        certBytes);
}

// Return:
//  +1 - Success with all certificates removed.
//  -1 - Partial Success. Removed at least one certificate. Failed to
//       remove one or more certificates.
//   0 - Error, unable to remove any certificates.
int MSCRYPT_remove_disallowed_certs(
    const uuid_t correlationId,
    MSCRYPT_SHARED_MEM *sharedMem,  // Optional
    int certFormat,
    int certLength,
    const unsigned char *certBytes)
{
    return MSCRYPT_CLIENT_cert_ctrl(
        correlationId,
        sharedMem,
        MSCRYPT_CERT_CTRL_REMOVE,
        MSCRYPT_CERT_LOCATION_DISALLOWED,
        certFormat,
        certLength,
        certBytes);
}


// OPENSSLDIR "/" "disallowed"
// MSCRYPT_free() returned directory name
static char *_get_disallowed_dir()
{
    const char *openSslDir = MSCRYPTP_get_default_cert_area();
    size_t openSslDirLength = strlen(openSslDir);
    const char *subDir = "disallowed";
    size_t subDirLength = strlen(subDir);
    size_t disallowedDirLength = openSslDirLength + 1 + subDirLength + 1;
    char *disallowedDir = (char *) MSCRYPT_zalloc(disallowedDirLength);

    if (disallowedDir != NULL) {
        BIO_snprintf(disallowedDir, disallowedDirLength, "%s/%s",
            openSslDir, subDir);
    }

    return disallowedDir;
}

// For success, returns length of tbs. Otherwise, returns 0 for any error.
int MSCRYPTP_X509_extract_tbs(
    int x509Length,
    const unsigned char *x509Bytes,
    const unsigned char **tbsBytes
    )
{
    int ret = 0;
    int inf = 0;
    int tag = 0;
    int class = 0;
    const unsigned char *cur = x509Bytes;
    long rem = (long) x509Length;
    const unsigned char *end = cur + rem;
    long len = 0;
    long hdrLen = 0;
    
    *tbsBytes = NULL;

    // Step into outer X509 SEQUENCE. cur is updated with the start of the SEQUENCE contents.
    inf = ASN1_get_object(
        &cur,
        &len, 
        &tag,
        &class,
        rem);
    if (inf != V_ASN1_CONSTRUCTED || tag != V_ASN1_SEQUENCE ||
            cur > end || len == 0 || 
            (rem = (long) (end - cur), len > rem)) {
        goto end;
    }

    *tbsBytes = cur;

    rem = len;
    end = cur + rem;
    // Step into the inner tbs SEQUENCE. cur is advanced past the tbs SEQUENCE tag/length header octets
    inf = ASN1_get_object(
        &cur,
        &len, 
        &tag,
        &class,
        rem);
    if (inf != V_ASN1_CONSTRUCTED || tag != V_ASN1_SEQUENCE ||
            cur > end || len == 0 ||
            (rem = (long) (end - cur), len > rem)) {
        goto end;
    }

    // total length is the tag/length bytes + the content length
    hdrLen = (long) (cur - *tbsBytes);
    ret = (int) (hdrLen + len);

end:
    return ret;
}
    

// returns -2 for error
int MSCRYPTP_X509_tbs_cmp(
    const uuid_t correlationId,
    const char *title,
    X509 *a,
    X509 *b)
{
    int ret;
    int aX509Len = 0;
    unsigned char *aX509Bytes = NULL;   // OPENSSL_free()
    int aTbsLen = 0;
    const unsigned char *aTbsBytes = NULL;

    int bX509Len = 0;
    unsigned char *bX509Bytes = NULL;   // OPENSSL_free()
    int bTbsLen = 0;
    const unsigned char *bTbsBytes = NULL;

    ERR_clear_error();

    aX509Len = i2d_X509(a, &aX509Bytes);
    bX509Len = i2d_X509(b, &bX509Bytes);

    if (aX509Len <= 0 || bX509Len <= 0) {
        MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, "i2d_X509");
        ret = -2;
        goto end;
    }

    aTbsLen = MSCRYPTP_X509_extract_tbs(aX509Len, aX509Bytes, &aTbsBytes);
    bTbsLen = MSCRYPTP_X509_extract_tbs(bX509Len, bX509Bytes, &bTbsBytes);

    if (aTbsLen <= 0 || bTbsLen <= 0) {
        MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, "MSCRYPTP_X509_extract_tbs");
        ret = -2;
        goto end;
    }

    ret = aTbsLen - bTbsLen;

    if (ret == 0 && aTbsLen != 0) {
        ret = memcmp(aTbsBytes, bTbsBytes, aTbsLen);
    }

    if (ret < 0) {
        ret = -1;
    }

end:
    OPENSSL_free(aX509Bytes);
    OPENSSL_free(bX509Bytes);

    return ret;
}


static void _X509_NAME_filename_hex_hash(
    X509_NAME *x,
    char *hexHash)
{
    unsigned long nameHash = X509_NAME_hash(x);
    BIO_snprintf(hexHash, MSCRYPTP_MAX_FILENAME_HEX_HASH_LENGTH, "%08lx", nameHash);
}

static const EVP_MD *_X509_tbs_hash_type(
    const uuid_t correlationId,
    const char *title,
    X509 *x)
{
    const char *loc = "";
    const EVP_MD *type = NULL;
    int signid = 0;
    int mdnid = 0;

    ERR_clear_error();

    signid = X509_get_signature_nid(x);
    if (signid == 0) {
        loc = "X509_get_signature_nid";
        goto openSslErr;
    }

    if (!OBJ_find_sigid_algs(signid, &mdnid, NULL)) {
        loc = "OBJ_find_sigid_algs";
        goto openSslErr;
    }

    type = EVP_get_digestbynid(mdnid);
    if (type == NULL) {
        loc = "EVP_get_digestbynid";
        goto openSslErr;
    }

end:
    return type;
openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
        
}

static int _X509_tbs_hash(
    const uuid_t correlationId,
    const char *title,
    X509 *x,
    const EVP_MD *otherType,                        // Optional
    unsigned char sha256md[SHA256_DIGEST_LENGTH],
    unsigned char othermd[EVP_MAX_MD_SIZE],         // Optional, depends on otherType
    unsigned int *othermdLen)                       // Optional, depends on otherType
{
    const char *loc = "";
    int ret = 0;
    int x509Len = 0;
    unsigned char *x509Bytes = NULL;    // OPENSSL_free()
    int tbsLen = 0;
    const unsigned char *tbsBytes = NULL;

    if (othermdLen != NULL) {
        *othermdLen = 0;
    }

    ERR_clear_error();

    x509Len = i2d_X509(x, &x509Bytes);
    if (x509Len <= 0) {
        loc = "i2d_X509";
        goto openSslErr;
    }
    tbsLen = MSCRYPTP_X509_extract_tbs(x509Len, x509Bytes, &tbsBytes);
    if (tbsLen <= 0) {
        loc = "MSCRYPTP_X509_extract_tbs";
        goto openSslErr;
    }

    if (!EVP_Digest(tbsBytes, tbsLen, sha256md, NULL, EVP_sha256(), NULL)) {
        loc = "EVP_Digest(sha256)";
        goto openSslErr;
    }

    ret = 1;

    if (otherType == NULL || othermd == NULL || othermdLen == NULL) {
        goto end;
    }

    // Only log failures

    if (!EVP_Digest(tbsBytes, tbsLen, othermd, othermdLen, otherType, NULL)) {
        loc = "EVP_Digest(other)";
        *othermdLen = 0;
        goto openSslErr;
    }

end:
    OPENSSL_free(x509Bytes);
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}



static int _X509_tbs_filename_hex_hash(
    const uuid_t correlationId,
    const char *title,
    X509 *x,
    char *hexHash)
{
    int ret = 0;
    unsigned char sha256md[SHA256_DIGEST_LENGTH];
    int fileHashLen;

    ret = _X509_tbs_hash(
        correlationId,
        title,
        x,
        NULL,                       // EVP_MD *otherType
        sha256md,
        NULL,                       // unsigned char othermd[EVP_MAX_MD_SIZE]
        NULL);                      // unsigned int *othermdLen

    if (ret) {
        fileHashLen = sizeof(sha256md);
        if (fileHashLen > MSCRYPTP_MAX_FILENAME_HASH_LENGTH) {
            fileHashLen = MSCRYPTP_MAX_FILENAME_HASH_LENGTH;
        }

        MSCRYPTP_bytes_to_hex(
            fileHashLen,
            sha256md,
            hexHash);
    }
end:
    return ret;
}

static void _X509_sha1_hex_hash(
    X509 *x,
    char *hexHash)
{
    unsigned char md[SHA_DIGEST_LENGTH];

    X509_digest(x, EVP_sha1(), md, NULL);
    MSCRYPTP_bytes_to_hex(
        sizeof(md),
        md,
        hexHash);
}

int MSCRYPTP_rename_file(
    const uuid_t correlationId,
    const char *title,
    const char *oldFilename,
    const char *newFilename)
{
    int ret = 0;

    // This will fail on windows. Need to remove first
    if (rename(oldFilename, newFilename) == 0) {
        MSCRYPTP_trace_log_para(correlationId, MSCRYPTP_TRACELOG_VERBOSE_FLAG, title, "Rename",
            "old: %s new: %s", oldFilename, newFilename);
        ret = 1;
    } else {
        int err = errno;
        MSCRYPTP_trace_log_errno_para(correlationId, 0, title, "Rename", err,
            "old: %s new: %s", oldFilename, newFilename);

        if (err == EEXIST || err == EACCES) {
            if (remove(newFilename) == 0) {
                if (rename(oldFilename, newFilename) == 0) {
                    MSCRYPTP_trace_log_para(correlationId, MSCRYPTP_TRACELOG_VERBOSE_FLAG, title, "RenameAfterRemove",
                        "old: %s new: %s", oldFilename, newFilename);
                    ret = 1;
                } else {
                    err = errno;
                    MSCRYPTP_trace_log_errno_para(correlationId, 0, title, "RenameAfterRemove", err,
                        "old: %s new: %s", oldFilename, newFilename);
                }
            } else {
                err = errno;
                MSCRYPTP_trace_log_errno_para(correlationId, 0, title, "Remove", err,
                    "new: %s", newFilename);
            }
        }
    }

    return ret;
}

#define MSCRYPTP_MAX_FILE_SEQ_INDEX    1024

static int _cert_remove(
    const uuid_t correlationId,
    const char *title,
    int removeIndex,
    const char *dirName,
    const char *sha1HexHash,
    const char *filenameHexHash,
    int filenameLength,
    const char *removeFilename)
{
    const char *loc = "";
    int ret = 0;
    int renameIndex = 0;
    char *renameFilename = NULL;  //  MSCRYPT_free()

    renameFilename = (char *) MSCRYPT_zalloc(filenameLength);
    if (renameFilename == NULL) {
        goto end;
    }

    // Find the last entry after the entry being removed
    for (int i = removeIndex + 1; i <= MSCRYPTP_MAX_FILE_SEQ_INDEX; i++) {
        BIO *in = NULL;
        X509 *fileCert = NULL;
        BIO_snprintf(renameFilename, filenameLength, "%s/%s.%d",
            dirName, filenameHexHash, i);

        in = BIO_new_file(renameFilename, "r");
        if (in == NULL) {
            break;
        }

        fileCert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
        BIO_free(in);
        if (fileCert == NULL) {
            MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, "PEM_read_bio_X509_AUX",
                "filename: %s", renameFilename);
            break;
        }

        X509_free(fileCert);
        renameIndex = i;
        MSCRYPTP_trace_log_para(correlationId, MSCRYPTP_TRACELOG_VERBOSE_FLAG, title, "AfterRemove",
            "filename: %s", renameFilename);
    }

    if (renameIndex == 0) {
        if (remove(removeFilename) == 0) {
            MSCRYPTP_trace_log_para(correlationId, MSCRYPTP_TRACELOG_VERBOSE_FLAG, title, "Remove",
                "sha1: %s filename: %s", sha1HexHash, removeFilename);
            ret = 1;
        } else {
            int err = errno;
            MSCRYPTP_trace_log_errno_para(correlationId, 0, title, "Remove", err,
                "sha1: %s filename: %s", sha1HexHash, removeFilename);
        }
    } else {
        MSCRYPTP_trace_log_para(correlationId, MSCRYPTP_TRACELOG_VERBOSE_FLAG, title, "Remove",
            "sha1: %s filename: %s", sha1HexHash, removeFilename);
        BIO_snprintf(renameFilename, filenameLength, "%s/%s.%d",
            dirName, filenameHexHash, renameIndex);
        ret = MSCRYPTP_rename_file(correlationId, title, renameFilename, removeFilename);
    }

end:
    MSCRYPT_free(renameFilename);
    return ret;
}

static int _is_identical_root(
    const uuid_t correlationId,
    const char *title,
    X509 *cert,
    X509 *fileCert)
{
    const char *loc = "";
    int ret = 0;
    BIO *mem = BIO_new(BIO_s_mem());
    BIO *fileMem = BIO_new(BIO_s_mem());
    int memLen = 0;
    const unsigned char *memBytes = NULL;
    int fileMemLen = 0;
    const unsigned char *fileMemBytes = NULL;

    if (mem == NULL || fileMem == NULL) {
        goto openSslErr; 
    }

    if (!PEM_write_bio_X509_AUX(mem, cert) || !PEM_write_bio_X509_AUX(fileMem, fileCert)) {
        loc = "PEM_write_bio_X509_AUX";
        goto openSslErr;
    }

    memLen = (int) BIO_get_mem_data(mem, (char **) &memBytes);
    fileMemLen = (int) BIO_get_mem_data(fileMem, (char **) &fileMemBytes);

    if (memLen == 0 || memLen != fileMemLen || memcmp(memBytes, fileMemBytes, memLen) != 0) {
        MSCRYPTP_trace_log(correlationId, MSCRYPTP_TRACELOG_VERBOSE_FLAG, title, "DifferentNewRootBytes");
        goto end;
    }

    ret = 1;
end:
    BIO_free(mem);
    BIO_free(fileMem);

    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

static int _cert_ctrl2(
    const uuid_t correlationId,
    int ctrl,
    int location,
    X509 *cert,
    char filenameHexHash[MSCRYPTP_MAX_FILENAME_HEX_HASH_LENGTH])
{
    const char *title = MSCRYPTP_get_cert_ctrl_title(ctrl, location);
    const char *loc = "";
    int ret = 0;
    int isRoot = 0;
    char sha1HexHash[SHA_DIGEST_LENGTH * 2 + 1];
    const char *dirName = NULL;                 // Don't free
    char *disallowedDirName = NULL;             // MSCRYPT_free()
    int filenameLength = 0;
    char *filename = NULL;                      // MSCRYPT_free()
    int tmpFilenameLength = 0;
    char *tmpFilename = NULL;                   // MSCRYPT_free()
    char *outFilename = NULL;                   // Don't free
    int i = 0;
    int cmpResult = -1;
    BIO *out = NULL;
    X509 *fileCert = NULL;
    
    _X509_sha1_hex_hash(cert, sha1HexHash);

    if (location == MSCRYPT_CERT_LOCATION_ROOT && ctrl != MSCRYPT_CERT_CTRL_FIND) {
        // Check if self-issued root certificate
        if (X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) == 0) {
            isRoot = 1;
        }
    }

    if (location == MSCRYPT_CERT_LOCATION_DISALLOWED) {
        disallowedDirName = _get_disallowed_dir();
        if (disallowedDirName == NULL) {
            loc = "_get_disallowed_dir";
            goto openSslErr;
        }
        dirName = disallowedDirName;
    } else {
        // Certificates are stored in the following directory
        dirName = MSCRYPTP_get_default_cert_dir();
    }

    // Here is an example certificate filename
    // "C:\Program Files\Common Files\SSL/certs/c4c48f78.0"

    // "C:\Program Files\Common Files\SSL/certs "/" "c4c48f78" "." "012345" "\0"
    //                                           0   01234567   0   012345   0

    filenameLength = (int) strlen(dirName) + 1 + (int) strlen(filenameHexHash) + 1 + 6 + 1;
    filename = (char *) MSCRYPT_zalloc(filenameLength);
    if (filename == NULL) {
        goto end;
    }

    for (i = 0; i <= MSCRYPTP_MAX_FILE_SEQ_INDEX; i++) {
        BIO *in = NULL;
        BIO_snprintf(filename, filenameLength, "%s/%s.%d",
            dirName, filenameHexHash, i);

        in = BIO_new_file(filename, "r");
        if (in == NULL) {
            if (ERR_GET_REASON(ERR_peek_last_error()) != BIO_R_NO_SUCH_FILE) {
                MSCRYPTP_trace_log_openssl_error_para(correlationId,
                    MSCRYPTP_TRACELOG_WARNING_FLAG, title, "BIO_new_file",
                    "sha1: %s filename: %s", sha1HexHash, filename);
            }
            break;
        }

        X509_free(fileCert);
        fileCert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
        BIO_free(in);
        if (fileCert == NULL) {
            MSCRYPTP_trace_log_openssl_error_para(correlationId, 
                MSCRYPTP_TRACELOG_WARNING_FLAG, title, "PEM_read_bio_X509_AUX",
                "sha1: %s filename: %s", sha1HexHash, filename);
            break;
        }

        if (ctrl == MSCRYPT_CERT_CTRL_FIND &&
                location == MSCRYPT_CERT_LOCATION_DISALLOWED) {
            cmpResult = MSCRYPTP_X509_tbs_cmp(correlationId, title, cert, fileCert);
        } else {
            cmpResult = X509_cmp(cert, fileCert);
        }

        if (cmpResult == 0) {
            break;
        }

        MSCRYPTP_trace_log_para(correlationId, MSCRYPTP_TRACELOG_VERBOSE_FLAG, title, "FilenameHashCollision",
            "sha1: %s filename: %s", sha1HexHash, filename);
    }

    if (i > MSCRYPTP_MAX_FILE_SEQ_INDEX) {
        MSCRYPTP_trace_log_error(correlationId, 0, title, "IndexCount", "Exceeded file count with same hash");
        goto end;
    }

    if (ctrl == MSCRYPT_CERT_CTRL_FIND) {
        if (cmpResult == 0) {
            ret = 1;
        }
        goto end;
    } else if (ctrl == MSCRYPT_CERT_CTRL_REMOVE) {
        if (cmpResult != 0) {
            MSCRYPTP_trace_log_error_para(correlationId,
                MSCRYPTP_TRACELOG_VERBOSE_FLAG | MSCRYPTP_TRACELOG_WARNING_FLAG,
                title, "Remove", "Certificate already removed",
                "sha1: %s filenameHexHash: %s", sha1HexHash, filenameHexHash);
            ret = 1;
            goto end;
        }

        ret = _cert_remove(
                    correlationId,
                    title,
                    i,
                    dirName,
                    sha1HexHash,
                    filenameHexHash,
                    filenameLength,
                    filename);
        goto end;
    }

    if (cmpResult == 0) {
        if (isRoot) {
            if (_is_identical_root(correlationId, title, cert, fileCert)) {
                MSCRYPTP_trace_log_error_para(correlationId,
                    MSCRYPTP_TRACELOG_VERBOSE_FLAG | MSCRYPTP_TRACELOG_WARNING_FLAG,
                    title, "ImportRoot", "Already exists",
                    "sha1: %s filename: %s", sha1HexHash, filename);
                ret = 1;
                goto end;
            }
        } else {
            MSCRYPTP_trace_log_error_para(correlationId,
                MSCRYPTP_TRACELOG_VERBOSE_FLAG | MSCRYPTP_TRACELOG_WARNING_FLAG,
                title, "Import", "Already exists",
                "sha1: %s filename: %s", sha1HexHash, filename);
            ret = 1;
            goto end;
        }

        // filename + ".tmp"
        //             0123
        tmpFilenameLength = filenameLength + 4;
        tmpFilename = (char *) MSCRYPT_zalloc(tmpFilenameLength);
        if (tmpFilename == NULL) {
            goto openSslErr;
        }

        BIO_snprintf(tmpFilename, tmpFilenameLength, "%s.tmp", filename);
        outFilename = tmpFilename;
        MSCRYPTP_trace_log_para(correlationId, MSCRYPTP_TRACELOG_VERBOSE_FLAG, title, "TempUpdateRoot",
            "filename: %s", tmpFilename);
    } else {
        outFilename = filename;
    }

    out = BIO_new_file(outFilename, "w");
    if (out == NULL) {
        MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, "BIO_new_file",
            "sha1: %s filename: %s", sha1HexHash, outFilename);
        goto end;
    }

    if (isRoot) {
        ret = PEM_write_bio_X509_AUX(out, cert);
    } else {
        ret = PEM_write_bio_X509(out, cert);
    }

    if (ret) {
        MSCRYPTP_trace_log_para(correlationId, MSCRYPTP_TRACELOG_VERBOSE_FLAG,
            title, isRoot ? "PEM_write_bio_X509_AUX" : "PEM_write_bio_X509",
            "sha1:%s filename: %s isRoot: %d", sha1HexHash, outFilename, isRoot);
    } else {
        MSCRYPTP_trace_log_openssl_error_para(correlationId, 0,
            title, isRoot ? "PEM_write_bio_X509_AUX" : "PEM_write_bio_X509",
            "sha1:%s filename: %s isRoot: %d", sha1HexHash, outFilename, isRoot);
        goto end;
    }

    BIO_flush(out);

    if (tmpFilename) {
        BIO_free(out);  // To ensure the file is closed before rename.
        out = NULL;

        ret = MSCRYPTP_rename_file(correlationId, title, tmpFilename, filename);
    }

end:
    X509_free(fileCert);
    MSCRYPT_free(disallowedDirName);
    MSCRYPT_free(filename);
    MSCRYPT_free(tmpFilename);
    BIO_free(out);
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

static int _cert_ctrl(
    const uuid_t correlationId,
    int ctrl,
    int location,
    X509 *cert)
{
    const char *title = MSCRYPTP_get_cert_ctrl_title(ctrl, location);
    int ret = 0;
    char filenameHexHash[MSCRYPTP_MAX_FILENAME_HEX_HASH_LENGTH];

    if (location == MSCRYPT_CERT_LOCATION_DISALLOWED) {
        if (!_X509_tbs_filename_hex_hash(correlationId, title, cert, filenameHexHash)) {
            goto end;
        }
    } else {
        // Certificates are identified via their subject name hash
        _X509_NAME_filename_hex_hash(X509_get_subject_name(cert), filenameHexHash);
    }

    ret = _cert_ctrl2(
        correlationId,
        ctrl,
        location,
        cert,
        filenameHexHash);

end:
    return ret;
}

static int _der_cert_ctrl(
    const uuid_t correlationId,
    int ctrl,
    int location,
    int length,
    const unsigned char *bytes)
{
    const char *title = MSCRYPTP_get_cert_ctrl_title(ctrl, location);
    int ret = 0;
    X509 *cert = d2i_X509(NULL, &bytes, length);

    if (cert == NULL) {
        MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, "d2i_X509");
        goto end;
    }

    ret = _cert_ctrl(
        correlationId,
        ctrl,
        location,
        cert);

end:
    X509_free(cert);
    return ret;
}

// From onecore\ds\security\cryptoapi\pki\certstor\newstor.cpp

//+-------------------------------------------------------------------------
//  Store file definitions
//
//  The file consist of the FILE_HDR followed by 1 or more FILE_ELEMENTs.
//  Each FILE_ELEMENT has a FILE_ELEMENT_HDR + its value.
//
//  First the CERT elements are written. If a CERT has any properties, then,
//  the PROP elements immediately precede the CERT's element. Next the CRL
//  elements are written. If a CRL has any properties, then, the PROP elements
//  immediately precede the CRL's element. Likewise for CTL elements and its
//  properties. Finally, the END element is written.
//--------------------------------------------------------------------------
typedef struct _FILE_HDR {
    unsigned int               dwVersion;
    unsigned int               dwMagic;
} FILE_HDR, *PFILE_HDR;

#define CERT_FILE_VERSION_0             0
#define CERT_MAGIC ((unsigned int)'C'+((unsigned int)'E'<<8)+((unsigned int)'R'<<16)+((unsigned int)'T'<<24))

// The element's data follows the HDR
typedef struct _FILE_ELEMENT_HDR {
    unsigned int               dwEleType;
    unsigned int               dwEncodingType;
    unsigned int               dwLen;
} FILE_ELEMENT_HDR, *PFILE_ELEMENT_HDR;

#define FILE_ELEMENT_END_TYPE           0
// FILE_ELEMENT_PROP_TYPEs              !(0 | CERT | CRL | CTL | KEYID)
// Note CERT_KEY_CONTEXT_PROP_ID (and CERT_KEY_PROV_HANDLE_PROP_ID)
// isn't written
#define FILE_ELEMENT_CERT_TYPE          32
#define FILE_ELEMENT_CRL_TYPE           33
#define FILE_ELEMENT_CTL_TYPE           34
#define FILE_ELEMENT_KEYID_TYPE         35

//#define MAX_FILE_ELEMENT_DATA_LEN       (4096 * 16)
#define MAX_FILE_ELEMENT_DATA_LEN       0xFFFFFFFF

typedef struct _MEMINFO {
    const unsigned char     *p;
    int                     len;
    int                     offset;
} MEMINFO, *PMEMINFO;

static void _sst_mem_init(
    MEMINFO *memInfo,
    const unsigned char *p,
    int len)
{
    memset(memInfo, 0, sizeof(*memInfo));
    memInfo->p = p;
    memInfo->len = len;
}

static int _sst_mem_read(
    MEMINFO *memInfo,
    void *out,
    int len)
{
    int readCount = len;

    if (memInfo->offset + len > memInfo->len) {
        readCount = memInfo->len - memInfo->offset;
    }

    if (readCount > 0) {
        memcpy(out, memInfo->p + memInfo->offset, readCount);
        memInfo->offset += readCount;
    }

    return readCount;
}

static int _sst_mem_tell(
    MEMINFO *memInfo)
{
    return memInfo->offset;
}

static void _sst_mem_seek(
    MEMINFO *memInfo,
    int offset)
{
    if (offset < memInfo->len) {
        memInfo->offset = offset;
    } else {
        memInfo->offset = memInfo->len;
    }
}
    

// Returns:
//  +1 - BIO *in is pointing to the start of the next certificate.
//       *certOffset - start of certificate
//       *certLength - certificate length
//   0 - sst format error
//  -1 - no more certificates
static int _sst_next_cert(
    const uuid_t correlationId,
    const char *title,
    MEMINFO *memInfo,
    int sstLength,
    int *certOffset,
    int *certLength)
{
    const char *loc = "";
    int ret = 0;
    FILE_ELEMENT_HDR eleHdr;
    int hasProp = 0;

    *certOffset = 0;
    *certLength = 0;

    for (;;) {
        int offset;

        if (_sst_mem_read(memInfo, &eleHdr, sizeof(eleHdr)) != sizeof(eleHdr)) {
            loc = "ReadEleHdr";
            goto sstErr;
        }

        if (eleHdr.dwEleType == FILE_ELEMENT_END_TYPE) {
            if (hasProp) {
                loc = "PrematureEndError";
                goto sstErr;
            }

            ret = -1;
            goto end;
        }

        offset = _sst_mem_tell(memInfo);
        if (offset > sstLength ||
                (int) eleHdr.dwLen > sstLength ||
                offset + (int) eleHdr.dwLen > sstLength) {
            loc = "ExceedEleSizeError";
            goto sstErr;
        }

        switch (eleHdr.dwEleType) {
            case FILE_ELEMENT_CERT_TYPE:
                *certOffset = offset;
                *certLength = eleHdr.dwLen;
                ret = 1;
                goto end;

            case FILE_ELEMENT_CRL_TYPE:
            case FILE_ELEMENT_CTL_TYPE:
                hasProp = 0;
            default:
                hasProp = 1;
        }

        // Skip properties, CRL or CTL
        _sst_mem_seek(memInfo, offset + eleHdr.dwLen);
    }

end:
    return ret;

sstErr:
    MSCRYPTP_trace_log_error(correlationId, 0, title, loc, "Invalid SST format");
    goto end;
}

static int _sst_cert_ctrl(
    const uuid_t correlationId,
    int ctrl,
    int location,
    int sstLength,
    const unsigned char *sstBytes)
{
    const char *title = MSCRYPTP_get_cert_ctrl_title(ctrl, location);
    const char *loc = "";
    int ret = 0;
    int successCount = 0;
    int failedCount = 0;
    MEMINFO memInfo;
    FILE_HDR fileHdr;

    _sst_mem_init(&memInfo, sstBytes, sstLength);

    if (_sst_mem_read(&memInfo, &fileHdr, sizeof(fileHdr)) != sizeof(fileHdr)) {
        loc = "ReadFileHdr";
        goto sstErr;
    }

    if (fileHdr.dwVersion != CERT_FILE_VERSION_0 ||
            fileHdr.dwMagic != CERT_MAGIC) {
        loc = "VerifyFileHdr";
        goto sstErr;
    }

    for (int i = 0; ; i++) {
        int nextRet = 0;
        int certOffset = 0;
        int certLength = 0;

        nextRet = _sst_next_cert(
            correlationId,
            title,
            &memInfo,
            sstLength,
            &certOffset,
            &certLength);
        if (nextRet <= 0) {
            if (nextRet == 0) {
                failedCount++;
            }
            goto end;
        }

        if (_der_cert_ctrl(
                correlationId,
                ctrl,
                location,
                certLength,
                sstBytes + certOffset)) {
            ret = 1;
            successCount++;
        } else { 
            MSCRYPTP_trace_log_error_para(correlationId, 0, title, "_der_cert_ctrl", "Not updated",
                "entry: %d", i);
            failedCount++;
        }

        _sst_mem_seek(&memInfo, certOffset + certLength);
    }

end:
    if (ret && failedCount) {
        ret = -1;
    }

    if (ret > 0) {
        MSCRYPTP_trace_log_para(correlationId, 0, title, "Complete",
            "updatedCount: %d", successCount);
    } else {
        MSCRYPTP_trace_log_error_para(correlationId, 0, title, "Complete", ret < 0 ? "Partial updates" : "No updates",
            "updatedCount: %d failedCount: %d", successCount, failedCount);
    }
    return ret;

sstErr:
    MSCRYPTP_trace_log_error(correlationId, 0, title, loc, "Invalid SST format");
    goto end;
}

static int _pem_cert_ctrl(
    const uuid_t correlationId,
    int ctrl,
    int location,
    int length,
    const unsigned char *bytes)
{
    const char *title = MSCRYPTP_get_cert_ctrl_title(ctrl, location);
    const char *loc = "";
    int ret = 0;
    int successCount = 0;
    int failedCount = 0;
    BIO *in = NULL;
    char *pemName = NULL;               // OPENSSL_free()
    char *pemHeader = NULL;             // OPENSSL_free()
    unsigned char *pemData = NULL;      // OPENSSL_free()
    X509 *cert = NULL;                  // X509_free()

    in = BIO_new_mem_buf(bytes, length);
    if (in == NULL) {
        goto openSslErr;
    }

    for (int i = 0;; i++) {
        long pemLen = 0;

        OPENSSL_free(pemName);
        pemName = NULL;
        OPENSSL_free(pemHeader);
        pemHeader = NULL;
        OPENSSL_free(pemData);
        pemData = NULL;
        X509_free(cert);
        cert = NULL;

        ERR_clear_error();
        if (!PEM_read_bio(in, &pemName, &pemHeader, &pemData, &pemLen)) {
            unsigned long err = ERR_peek_last_error();

            if (ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
                break;
            }

            failedCount++;
            loc = "PEM_read_bio";
            goto openSslErr;
        }

        if (strcmp(pemName, PEM_STRING_X509) == 0 ||
                strcmp(pemName, PEM_STRING_X509_TRUSTED) == 0 ||
                strcmp(pemName, PEM_STRING_X509_OLD) == 0) {
            const unsigned char *data = pemData;

            cert = d2i_X509_AUX(NULL, &data, pemLen);
            if (cert == NULL) {
                data = pemData;
                cert = d2i_X509(NULL, &data, pemLen);
            }
        }

        if (cert == NULL) {
            MSCRYPTP_trace_log_error_para(correlationId, MSCRYPTP_TRACELOG_WARNING_FLAG,
                title, "IsCertPEM", "Not a certificate",
                "entry: %d name: %s", i, pemName);
            continue;
        }

        if (_cert_ctrl(
                correlationId,
                ctrl,
                location,
                cert)) {
            ret = 1;
            successCount++;
        } else { 
            MSCRYPTP_trace_log_error_para(correlationId, 0, title, "_cert_ctrl", "Not updated",
                "entry: %d name: %s", i, pemName);
            failedCount++;
        }
    }

end:
    OPENSSL_free(pemName);
    OPENSSL_free(pemHeader);
    OPENSSL_free(pemData);
    X509_free(cert);
    BIO_free(in);

    if (ret && failedCount) {
        ret = -1;
    }

    if (ret > 0) {
        MSCRYPTP_trace_log_para(correlationId, 0, title, "Complete",
            "updatedCount: %d", successCount);
    } else {
        MSCRYPTP_trace_log_error_para(correlationId, 0, title, "Complete", ret < 0 ? "Partial updates" : "No updates",
            "updatedCount: %d failedCount: %d", successCount, failedCount);
    }

    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

int MSCRYPT_SERVER_cert_ctrl(
    const uuid_t correlationId,
    int ctrl,
    int location,
    int format,
    int length,
    const unsigned char *bytes)
{
    const char *title = MSCRYPTP_get_cert_ctrl_title(ctrl, location);
    int ret = 0;

    ERR_clear_error();

#ifndef MSCRYPT_TEST_WINDOWS
    // Only one thread at a time can update the certificate directories
    if (location == MSCRYPT_CERT_LOCATION_DISALLOWED) {
        // Separate lock for disallowed. Don't want to block adding roots
        G_LOCK(MSCRYPT_certCtrlDisallowedLock);
    } else {
        G_LOCK(MSCRYPT_certCtrlLock);
    }
#endif

    switch (format) {
        case MSCRYPT_CERT_FORMAT_DER:
            ret = _der_cert_ctrl(
                correlationId,
                ctrl,
                location,
                length,
                bytes);
            break;

        case MSCRYPT_CERT_FORMAT_PEM:
            ret = _pem_cert_ctrl(
                correlationId,
                ctrl,
                location,
                length,
                bytes);
            break;

        case MSCRYPT_CERT_FORMAT_SST:
            ret = _sst_cert_ctrl(
                correlationId,
                ctrl,
                location,
                length,
                bytes);
            break;

        case MSCRYPT_CERT_FORMAT_CTL:
            ret = MSCRYPT_SERVER_ctl_ctrl(
                correlationId,
                ctrl,
                location,
                length,
                bytes);
            break;

        default:
            MSCRYPTP_trace_log_error(correlationId, 0, title, "Format", "Not supported");
    }

#ifndef MSCRYPT_TEST_WINDOWS
    if (location == MSCRYPT_CERT_LOCATION_DISALLOWED) {
        G_UNLOCK(MSCRYPT_certCtrlDisallowedLock);
    } else {
        G_UNLOCK(MSCRYPT_certCtrlLock);
    }
#endif

    return ret;
}


static int _read_is_installed_file(
    const uuid_t correlationId,
    const char *filename)
{
    const char *title = MSCRYPTP_IMPORT_TRUSTED_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *in = NULL;
    unsigned char buf[1];

    ERR_clear_error();

    in = BIO_new_file(filename, "rb");
    if (in == NULL) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != BIO_R_NO_SUCH_FILE) {
            loc = "BIO_new_file";
            goto openSslErr;
        }
        goto end;
    }

    if (BIO_read(in, buf, sizeof(buf)) != sizeof(buf)) {
        loc = "BIO_read";
        goto openSslErr;
    }

    if (buf[0] == 0) {
        loc = "Invalid Content";
        goto openSslErr;
    }

    ret = 1;

end:
    BIO_free(in);
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "filename: %s", filename);
    goto end;
}

static int _write_is_installed_file(
    const uuid_t correlationId,
    const char *filename)
{
    const char *title = MSCRYPTP_IMPORT_TRUSTED_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *out = NULL;
    unsigned char buf[1] = { 1 };

    ERR_clear_error();

    out = BIO_new_file(filename, "wb");
    if (out == NULL) {
        loc = "BIO_new_file";
        goto openSslErr;
    }

    if (BIO_write(out, buf, sizeof(buf)) != sizeof(buf)) {
        loc = "BIO_write";
        goto openSslErr;
    }
    BIO_flush(out);

    ret = 1;

end:
    BIO_free(out);
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "filename: %s", filename);
    goto end;
}

// MSCRYPT_free() returned path name
static char *_get_path_name(
    const char *dir,
    const char *subPath)
{
    size_t dirLength = strlen(dir);
    size_t subPathLength = strlen(subPath);
    size_t pathNameLength = dirLength + 1 + subPathLength + 1;
    char *pathName = (char *) MSCRYPT_zalloc(pathNameLength);

    if (pathName != NULL) {
        BIO_snprintf(pathName, pathNameLength, "%s/%s",
            dir, subPath);
    }

    return pathName;
}

#define MSCRYPTP_INSTALL_CERTS_FILENAME             "certs.pem"
#define MSCRYPTP_IMAGE_CERTS_INSTALLED_FILENAME     "imagecerts.installed"

int MSCRYPTP_install_image_certs(
    const uuid_t correlationId)
{
    const char *title = MSCRYPTP_IMPORT_TRUSTED_TITLE;
    const char *loc = "";
    int ret = 0;
    char *installedPath = NULL; // MSCRYPT_free()
    char *certsPath = NULL;     // MSCRYPT_free()
    BIO *in = NULL;
    BIO *mem = NULL;
    int inLength;
    unsigned char *inBytes;       // Don't free

    installedPath = _get_path_name(
        MSCRYPTP_get_default_cert_dir(),
        MSCRYPTP_IMAGE_CERTS_INSTALLED_FILENAME);
    if (installedPath == NULL) {
        goto end;
    }

    if (_read_is_installed_file(correlationId, installedPath)) {
        MSCRYPTP_trace_log_para(correlationId, 0, title, "Certificates already installed",
            "installed: %s", installedPath);
        goto success;
    }

    certsPath = _get_path_name(
        MSCRYPTP_get_install_image_dir(),
        MSCRYPTP_INSTALL_CERTS_FILENAME);
    if (certsPath == NULL) {
        goto end;
    }

    ERR_clear_error();

    in = BIO_new_file(certsPath, "rb");
    if (in == NULL) {
        loc = "BIO_new_file";
        goto openSslErr;
    }

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        loc = "BIO_new";
        goto openSslErr;
    }

    for (;;) {
        char buff[512];
        int inl = BIO_read(in, buff, sizeof(buff));

        if (inl <= 0) 
            break;
        if (BIO_write(mem, buff, inl) != inl) {
            loc = "BIO_write";
            goto openSslErr;
        }
    }

    inLength = (int) BIO_get_mem_data(mem, (char **) &inBytes);

    if (MSCRYPT_SERVER_cert_ctrl(
            correlationId,
            MSCRYPT_CERT_CTRL_IMPORT,
            MSCRYPT_CERT_LOCATION_ROOT,
            MSCRYPT_CERT_FORMAT_PEM,
            inLength,
            inBytes) <= 0) {
        goto end;
    }

    if (!_write_is_installed_file(correlationId, installedPath)) {
        goto end;
    }

    MSCRYPTP_trace_log_para(correlationId, 0, title, "Certificates successfully installed",
         "certs: %s installed: %s", certsPath, installedPath);

success:
    ret = 1;

end:
    MSCRYPT_free(installedPath);
    MSCRYPT_free(certsPath);
    BIO_free(in);
    BIO_free(mem);
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "filename: %s", certsPath);
    goto end;
}


// Return:
//  1 - Certificate is disallowed.
//  0 - Certificate not found in the disallowed certificates directory or not found in a disallowed CTL.
int _is_disallowed_cert2(
    const uuid_t correlationId,
    MSCRYPTP_CTLS_CTX *ctlsCtx,
    X509 *cert)
{
    const char *title = MSCRYPTP_IS_DISALLOWED_TITLE;
    const char *loc = "";
    int isDisallowed = 1;
    const EVP_MD *otherType = NULL;
    unsigned char sha256md[SHA256_DIGEST_LENGTH];
    unsigned char othermd[EVP_MAX_MD_SIZE];
    unsigned int othermdLen = 0;
    unsigned char pubmd[MD5_DIGEST_LENGTH];
    unsigned int pubmdLen = 0;
    int fileHashLen;
    char filenameHexHash[MSCRYPTP_MAX_FILENAME_HEX_HASH_LENGTH];

    otherType = _X509_tbs_hash_type(correlationId, title, cert);
    if (otherType == EVP_sha256()) {
        otherType = NULL;
    }

    if (!_X509_tbs_hash(
            correlationId,
            title,
            cert,
            otherType,
            sha256md,
            othermd,
            &othermdLen)) {
        loc = "_X509_tbs_hash";
        goto disallowedErr;
    }

    fileHashLen = sizeof(sha256md);
    if (fileHashLen > MSCRYPTP_MAX_FILENAME_HASH_LENGTH) {
        fileHashLen = MSCRYPTP_MAX_FILENAME_HASH_LENGTH;
    }

    MSCRYPTP_bytes_to_hex(
        fileHashLen,
        sha256md,
        filenameHexHash);

    if (_cert_ctrl2(
            correlationId,
            MSCRYPT_CERT_CTRL_FIND,
            MSCRYPT_CERT_LOCATION_DISALLOWED,
            cert,
            filenameHexHash)) {
        loc = "disallowed_cert";
        goto disallowedErr;
    }


    if (ctlsCtx == NULL) {
        isDisallowed = 0;
        goto end;
    }

    if (MSCRYPTP_is_cert_hash_in_disallowed_ctls_ctx(
            correlationId,
            ctlsCtx,
            sha256md,
            sizeof(sha256md))) {
        loc = "sha256_sig_in_disallowed_ctl";
        goto disallowedErr;
    }

    if (otherType != NULL && othermdLen != 0) {
        if (MSCRYPTP_is_cert_hash_in_disallowed_ctls_ctx(
                correlationId,
                ctlsCtx,
                othermd,
                othermdLen)) {
            loc = "other_sig_in_disallowed_ctl";
            goto disallowedErr;
        }
    }

    if (!X509_pubkey_digest(cert, EVP_md5(), pubmd, &pubmdLen) || pubmdLen != sizeof(pubmd)) {
        MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, "X509_pubkey_digest");
        goto end;
    }

    if (MSCRYPTP_is_cert_hash_in_disallowed_ctls_ctx(
            correlationId,
            ctlsCtx,
            pubmd,
            pubmdLen)) {
        loc = "pubkey_in_disallowed_ctl";
        goto disallowedErr;
    }

    isDisallowed = 0;
end:
    return isDisallowed;

disallowedErr:
    MSCRYPTP_trace_log_error(correlationId, 0, title, loc, "Disallowed Cert");
    goto end;
}

// Return:
//  1 - Certificate is disallowed.
//  0 - Certificate not found in the disallowed certificates directory.
int MSCRYPT_is_disallowed_cert(
    const uuid_t correlationId,
    X509 *cert)
{
    int isDisallowed = 1;
    uuid_t randId;
    MSCRYPTP_CTLS_CTX *ctlsCtx = NULL;
    if (correlationId == NULL) {
        RAND_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    ctlsCtx = MSCRYPTP_get_disallowed_ctls_ctx(correlationId);

    isDisallowed = _is_disallowed_cert2(
        correlationId,
        ctlsCtx,
        cert);

    MSCRYPTP_release_ctls_ctx(ctlsCtx);

    return isDisallowed;
}

typedef struct MSCRYPTP_verify_cert_callback_ctx_st MSCRYPTP_VERIFY_CERT_CALLBACK_CTX;
struct MSCRYPTP_verify_cert_callback_ctx_st {
    MSCRYPT_PFN_VERIFY_CERT_CALLBACK    callback;
    void                                *arg;
};

DEFINE_STACK_OF(MSCRYPTP_VERIFY_CERT_CALLBACK_CTX);

struct MSCRYPT_verify_cert_ctx_st {
    uuid_t                                      correlationId;
    STACK_OF(MSCRYPTP_VERIFY_CERT_CALLBACK_CTX) *callbackCtx;
    const X509_VERIFY_PARAM                     *param;
};


static void MSCRYPTP_VERIFY_CERT_CALLBACK_CTX_free(MSCRYPTP_VERIFY_CERT_CALLBACK_CTX *p) {
    MSCRYPT_free(p);
}


MSCRYPT_VERIFY_CERT_CTX *MSCRYPT_create_verify_cert_ctx(
    const uuid_t correlationId)
{
    MSCRYPT_VERIFY_CERT_CTX *ctx = NULL;

    ctx = (MSCRYPT_VERIFY_CERT_CTX *) MSCRYPT_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        goto end;
    }

    if (correlationId == NULL) {
        RAND_bytes(ctx->correlationId, sizeof(ctx->correlationId));
    } else {
        memcpy(ctx->correlationId, correlationId, sizeof(ctx->correlationId));
    }

end:
    return ctx;
}

void MSCRYPTP_get_verify_cert_ctx_correlationId(
    MSCRYPT_VERIFY_CERT_CTX *ctx,
    uuid_t correlationId)
{
    if (ctx) {
        memcpy(correlationId, ctx->correlationId, sizeof(ctx->correlationId));
    } else {
        memset(correlationId, 0, sizeof(ctx->correlationId));
    }
}

void MSCRYPT_free_verify_cert_ctx(
    MSCRYPT_VERIFY_CERT_CTX *ctx)
{
    if (ctx == NULL) {
        return;
    }

    sk_MSCRYPTP_VERIFY_CERT_CALLBACK_CTX_pop_free(
        ctx->callbackCtx,
        MSCRYPTP_VERIFY_CERT_CALLBACK_CTX_free);

    MSCRYPT_free(ctx);
}


int MSCRYPT_register_verify_cert_callback(
    MSCRYPT_VERIFY_CERT_CTX *ctx,
    MSCRYPT_PFN_VERIFY_CERT_CALLBACK callback,
    void *arg)
{
    const char *title = MSCRYPTP_VERIFY_CERT_TITLE;
    const char *loc = "";
    int ret = 0;
    MSCRYPTP_VERIFY_CERT_CALLBACK_CTX *callbackCtx = NULL;

    if (ctx->callbackCtx == NULL) {
        ctx->callbackCtx = sk_MSCRYPTP_VERIFY_CERT_CALLBACK_CTX_new_null();
        if (ctx->callbackCtx == NULL) {
            loc = "CALLBACK_CTX_new";
            goto openSslErr;
        }
    }

    callbackCtx = (MSCRYPTP_VERIFY_CERT_CALLBACK_CTX *) MSCRYPT_zalloc(sizeof(*callbackCtx));
    if (callbackCtx == NULL) {
        goto end;
    }

    callbackCtx->callback = callback;
    callbackCtx->arg = arg;

    if (!sk_MSCRYPTP_VERIFY_CERT_CALLBACK_CTX_push(ctx->callbackCtx, callbackCtx)) {
        MSCRYPT_free(callbackCtx);
        loc = "CALLBACK_CTX_push";
        goto openSslErr;
    }

    ret = 1;
end:
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(ctx->correlationId, 0, title, loc);
    goto end;
}

void MSCRYPT_set_verify_cert_param(
    MSCRYPT_VERIFY_CERT_CTX *ctx,
    const X509_VERIFY_PARAM *param)
{
    ctx->param = param;
}


static int _der_cert_load(
    const uuid_t correlationId,
    int certLength,
    const unsigned char *certBytes,
    X509 **cert)
{
    const char *title = MSCRYPTP_HELPER_CERT_TITLE;
    int ret = 0;

    *cert = d2i_X509(NULL, &certBytes, certLength);
    if (*cert == NULL) {
        MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, "d2i_X509");
        goto end;
    }

    ret = 1;
end:
    return ret;
}

int MSCRYPT_load_pem_cert(
    const uuid_t correlationId,
    int certLength,
    const unsigned char *certBytes,
    X509 **cert,
    STACK_OF(X509) **ca)
{
    const char *title = MSCRYPTP_HELPER_CERT_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *in = NULL;
    STACK_OF(X509_INFO) *certInfos = NULL;

    *cert = NULL;
    *ca = sk_X509_new_null();
    if (*ca == NULL) {
        loc = "sk_X509_new";
        goto openSslErr;
    }

    in = BIO_new_mem_buf(certBytes, certLength);
    if (in == NULL) {
        loc = "new_mem_buf";
        goto openSslErr;
    }

    certInfos = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
    if (certInfos == NULL) {
        loc = "PEM_X509_INFO_read_bio";
        goto openSslErr;
    }

    for (int i = 0; i < sk_X509_INFO_num(certInfos); i++) {
        X509_INFO *certInfo = sk_X509_INFO_value(certInfos, i);
        if (certInfo->x509 != NULL) {
            if (*cert == NULL) {
                *cert = certInfo->x509;
            } else {
                if (!sk_X509_push(*ca, certInfo->x509)) {
                    loc = "sk_X509_push";
                    goto openSslErr;
                }
            }

            X509_up_ref(certInfo->x509);
        }
    }

    if (!*cert) {
        MSCRYPTP_trace_log_error(correlationId, 0, title, loc, "No certificates in PEM");
        goto end;
    }

    ret = 1;

end:
    sk_X509_INFO_pop_free(certInfos, X509_INFO_free);
    BIO_free(in);

    if (!ret) {
        X509_free(*cert);
        *cert = NULL;
        sk_X509_pop_free(*ca, X509_free);
        *ca = NULL;
    }

    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

int MSCRYPTP_pem_from_certs(
    const uuid_t correlationId,
    X509 *cert,                     // Optional
    STACK_OF(X509) *ca,             // Optional
    int *pemCertLength,             // Excludes NULL terminator
    char **pemCert)                 // MSCRYPT_free()                   
{
    const char *title = MSCRYPTP_HELPER_CERT_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *mem = NULL;
    int memLen = 0;
    const unsigned char *memBytes = NULL;   // Don't free

    *pemCertLength = 0;
    *pemCert = NULL;

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        goto openSslErr;
    }

    if (cert != NULL) {
        if (!PEM_write_bio_X509(mem, cert)) {
            loc = "PEM_write_bio_X509";
            goto openSslErr;
        }
    }

    if (ca != NULL) {
        for (int i = 0; i < sk_X509_num(ca); i++) {
            if (!PEM_write_bio_X509(mem, sk_X509_value(ca, i))) {
                loc = "PEM_write_bio_X509";
                goto openSslErr;
            }
        }
    }

    memLen = (int) BIO_get_mem_data(mem, (char **) &memBytes);
    *pemCert = (char *) MSCRYPT_zalloc(memLen + 1);
    if (*pemCert == NULL) {
        goto openSslErr;
    }

    memcpy(*pemCert, memBytes, memLen);
    *pemCertLength = memLen;

    ret = 1;
end:
    BIO_free(mem);
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}


static X509_STORE *_setup_verify(
    const uuid_t correlationId)
{
    const char *title = MSCRYPTP_VERIFY_CERT_TITLE;
    const char *loc = "";
    X509_STORE *store = NULL;
    X509_LOOKUP *lookup = NULL;

    store = X509_STORE_new();
    if (store == NULL) {
        goto openSslErr;
    }

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
    if (lookup == NULL) {
        loc = "add_lookup";
        goto openSslErr;
    }

    if (!X509_LOOKUP_add_dir(lookup, MSCRYPTP_get_default_cert_dir(), X509_FILETYPE_PEM)) {
        loc = "add_dir";
        goto openSslErr;
    }

    ERR_clear_error();
    return store;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(correlationId, 0, title, loc);
    X509_STORE_free(store);
    return NULL;
}

// Cert sha1 hash of untrusted roots. Require trusted CAs.
static const char *MSCRYPTP_untrustedRoots[] = {
    // 653b494a.0 - (CN) Baltimore CyberTrust Root
    "d4de20d05e66fc53fe1a50882c78db2852cae474",

    NULL
};

static int MSCRYPTP_is_untrusted_root(
    X509 *cert)
{
    int ret = 0;
    char sha1HexHash[SHA_DIGEST_LENGTH * 2 + 1];

    _X509_sha1_hex_hash(cert, sha1HexHash);

    for (int i = 0; MSCRYPTP_untrustedRoots[i] != NULL; i++) {
        if (strcmp(sha1HexHash, MSCRYPTP_untrustedRoots[i]) == 0) {
            ret = 1;
            break;
        }
    }

    return ret;
}

// Return:
//  1 - Certificate is trusted.
//  0 - Certificate not found in the trusted certificates directory.
static int MSCRYPTP_is_trusted_ca(
    const uuid_t correlationId,
    X509 *cert)
{
    return _cert_ctrl(
        correlationId,
        MSCRYPT_CERT_CTRL_FIND,
        MSCRYPT_CERT_LOCATION_ROOT,
        cert);
}

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
    int *verifyChainError)
{
    const char *title = MSCRYPTP_VERIFY_CERT_TITLE;
    const char *loc = "";
    int ret = 0;
    int chainRet = 0;
    STACK_OF(X509) *storeChain = NULL;
    int chainDepth = 0;

    *verifyChainError = 0;

    ERR_clear_error();

    if (ctx->param != NULL) {
        X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(storeCtx);
        if (param == NULL) {
            MSCRYPTP_trace_log_error(ctx->correlationId, 0, title, "X509_STORE_CTX_get0_param", "Missing param");
        } else {
            X509_VERIFY_PARAM_inherit(param, ctx->param);
        }
    }

    // Following returns 1 for success;
    chainRet = X509_verify_cert(storeCtx);
    storeChain = X509_STORE_CTX_get1_chain(storeCtx);
    if (storeChain == NULL) {
        loc = "CTX_get1_chain";
        goto openSslErr;
    }

    chainDepth = sk_X509_num(storeChain);
    if (chainDepth <= 0) {
        MSCRYPTP_trace_log_error(ctx->correlationId, 0, title, "ChainDepth", "No certificates in chain");
        goto end;
    }

    if (chainRet > 0) {
        chainRet = 1;
    } else {
        // These errors are defined in x509_vfy.h
        //  X509_V_ERR_*
        *verifyChainError = X509_STORE_CTX_get_error(storeCtx);

        if ((mscryptFlags & MSCRYPT_IGNORE_DEPTH_ZERO_SELF_SIGNED_ERROR_FLAG) != 0 &&
                *verifyChainError == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT &&
                chainDepth == 1) {
            chainRet = 1;
            *verifyChainError = 0;
        } else {
            MSCRYPTP_trace_log_openssl_verify_cert_error(ctx->correlationId, 0, title,
                "X509_verify_cert", *verifyChainError);
            chainRet = -1;
        }
    }

    {
        MSCRYPTP_CTLS_CTX *ctlsCtx = MSCRYPTP_get_disallowed_ctls_ctx(ctx->correlationId);

        for (int i = 0; i < chainDepth; i++) {
            X509 *cert = sk_X509_value(storeChain, i);

            if (_is_disallowed_cert2(ctx->correlationId, ctlsCtx, cert)) {
                *verifyChainError = X509_V_ERR_CERT_REVOKED;
                X509_STORE_CTX_set_error(storeCtx, *verifyChainError);
                MSCRYPTP_trace_log_openssl_verify_cert_error(ctx->correlationId, 0, title,
                    "MSCRYPT_is_disallowed_cert", *verifyChainError);
                chainRet = -1;
            }
        }

        MSCRYPTP_release_ctls_ctx(ctlsCtx);
    }

    if (chainDepth >= 2) {
        X509 *root = sk_X509_value(storeChain, chainDepth - 1);

        if (MSCRYPTP_is_untrusted_root(root)) {
            X509 *ca = sk_X509_value(storeChain, chainDepth - 2);
            const char nullTerminator = 0;

            BIO *rootBio = NULL;
            BIO *caBio = NULL;
            const char *rootName = "";
            const char *caName = "";

            rootBio = BIO_new(BIO_s_mem());
            if (rootBio != NULL) {
                char *name = NULL;
                X509_NAME_print_ex(
                    rootBio,
                    X509_get_subject_name(root),
                    0,                      // indent
                    XN_FLAG_ONELINE | XN_FLAG_DN_REV);
                if (BIO_write(rootBio, &nullTerminator, 1) == 1 &&
                        BIO_get_mem_data(rootBio, &name) > 0 && name != NULL) {
                    rootName = name;
                }
            }

            caBio = BIO_new(BIO_s_mem());
            if (caBio != NULL) {
                char *name = NULL;
                X509_NAME_print_ex(
                    caBio,
                    X509_get_subject_name(ca),
                    0,                      // indent
                    XN_FLAG_ONELINE | XN_FLAG_DN_REV);
                if (BIO_write(caBio, &nullTerminator, 1) == 1 &&
                        BIO_get_mem_data(caBio, &name) > 0 && name != NULL) {
                    caName = name;
                }
            }

            if (!MSCRYPTP_is_trusted_ca(ctx->correlationId, ca)) {
                *verifyChainError = X509_V_ERR_CERT_REVOKED;
                X509_STORE_CTX_set_error(storeCtx, *verifyChainError);

                MSCRYPTP_trace_log_openssl_verify_cert_error_para(ctx->correlationId, 0, title,
                    "MSCRYPTP_is_untrusted_root", *verifyChainError,
                    "ROOT: <%s> CA: <%s>", rootName, caName);
                chainRet = -1;

            } else {
                MSCRYPTP_trace_log_para(ctx->correlationId, MSCRYPTP_TRACELOG_VERBOSE_FLAG, title,
                    "MSCRYPTP_is_trusted_ca", 
                    "ROOT: <%s> CA: <%s>", rootName, caName);
            }


            BIO_free(rootBio);
            BIO_free(caBio);
        }
    }

    for (int i = 0; i < sk_MSCRYPTP_VERIFY_CERT_CALLBACK_CTX_num(ctx->callbackCtx); i++) {
        MSCRYPTP_VERIFY_CERT_CALLBACK_CTX *callbackCtx =
            sk_MSCRYPTP_VERIFY_CERT_CALLBACK_CTX_value(ctx->callbackCtx, i);

        int callbackRet = callbackCtx->callback(
            ctx->correlationId,
            storeCtx,
            verifyChainError,
            callbackCtx->arg);
        if (callbackRet == 0) {
            MSCRYPTP_trace_log_error(ctx->correlationId, 0, title, "callback", "Callback verify error");
            goto end;
        }

        if (callbackRet < 0) {
            chainRet = -1;
            MSCRYPTP_trace_log_openssl_verify_cert_error(ctx->correlationId, 0, title, "callback", *verifyChainError);
        }
    }

    ret = chainRet;
    ERR_clear_error();
end: 
    sk_X509_pop_free(storeChain, X509_free);
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(ctx->correlationId, 0, title, loc);
    goto end;
}

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to build chain
int MSCRYPT_verify_cert2(
    MSCRYPT_VERIFY_CERT_CTX *ctx,   // Optional
    int mscryptFlags,
    X509 *cert,
    STACK_OF(X509) *ca,             // Optional
    int *verifyChainError,
    STACK_OF(X509) **chain)         // Optional
{
    const char *title = MSCRYPTP_VERIFY_CERT_TITLE;
    const char *loc = "";
    int ret = 0;
    int chainRet = 0;
    X509_STORE *store = NULL;
    X509_STORE_CTX *storeCtx = NULL;
    STACK_OF(X509) *storeChain = NULL;
    MSCRYPT_VERIFY_CERT_CTX *allocCtx = NULL;

    *verifyChainError = 0;
    if (chain) {
        *chain = NULL;
    }

    ERR_clear_error();

    if (ctx == NULL) {
        allocCtx = MSCRYPT_create_verify_cert_ctx(NULL);
        if (allocCtx == NULL) {
            return 0;
        }

        ctx = allocCtx;
    }

    if (chain) {
        *chain = sk_X509_new_null();
        if (*chain == NULL) {
            goto openSslErr;
        }
    }

    store = _setup_verify(ctx->correlationId);
    if (store == NULL) {
        goto end;
    }

    storeCtx = X509_STORE_CTX_new();
    if (storeCtx == NULL) {
        goto openSslErr;
    }

    if (!X509_STORE_CTX_init(storeCtx, store, cert, ca)) {
        loc = "CTX_init";
        goto openSslErr;
    }

    chainRet = MSCRYPTP_X509_verify_cert(
        ctx,
        storeCtx,
        mscryptFlags,
        verifyChainError);
    if (chainRet == 0) {
        goto end;
    }

    if (chain) {
        storeChain = X509_STORE_CTX_get1_chain(storeCtx);
        if (storeChain == NULL) {
            loc = "CTX_get1_chain";
            goto openSslErr;
        }

        for (int i = 0; i < sk_X509_num(storeChain); i++) {
            X509 *cert = sk_X509_value(storeChain, i);
            int isRoot = 0;

            if (X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) == 0) {
                isRoot = 1;
            }

            if (i == 0) {
                if (mscryptFlags & MSCRYPT_EXCLUDE_END_FLAG) {
                    continue;
                }
            } else if (isRoot && (mscryptFlags & MSCRYPT_EXCLUDE_ROOT_FLAG)) {
                continue;
            }

            if (!sk_X509_push(*chain, cert)) {
                goto openSslErr;
            }
            X509_up_ref(cert);
        }

        if (ca && !(mscryptFlags & MSCRYPT_EXCLUDE_EXTRA_CA_FLAG)) {
            for (int i = 0; i < sk_X509_num(ca); i++) {
                X509 *caCert = sk_X509_value(ca, i);
                int isOutMatch = 0;

                for (int j = 0; j < sk_X509_num(*chain); j++) {
                    X509 *outCert = sk_X509_value(*chain, j);
                    if (X509_cmp(caCert, outCert) == 0) {
                        isOutMatch = 1;
                        break;
                    }
                }

                if (!isOutMatch) {
                    if ((mscryptFlags & MSCRYPT_EXCLUDE_ROOT_FLAG) &&
                            X509_NAME_cmp(X509_get_subject_name(caCert),
                                X509_get_issuer_name(caCert)) == 0) {
                            // Exclude the root.
                            continue;
                    }

                    if (!sk_X509_push(*chain, caCert)) {
                        goto openSslErr;
                    }
                    X509_up_ref(caCert);
                }
            }
        }
    }

    ret = chainRet;
    ERR_clear_error();
end: 
    sk_X509_pop_free(storeChain, X509_free);
    X509_STORE_CTX_free(storeCtx);
    X509_STORE_free(store);
    MSCRYPT_free_verify_cert_ctx(allocCtx);

    if (!ret && chain) {
        sk_X509_pop_free(*chain, X509_free);
        *chain = NULL;
    }
    return ret;

openSslErr:
    MSCRYPTP_trace_log_openssl_error(ctx->correlationId, 0, title, loc);
    goto end;
}

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, other errors, such as, invalid input certificate.
int MSCRYPT_verify_cert(
    MSCRYPT_VERIFY_CERT_CTX *ctx,       // Optional
    int mscryptFlags,
    int certFormat,                     // Only DER and PEM
    int certLength,
    const unsigned char *certBytes,
    int *verifyChainError,
    int *pemChainLength,                // Optional, excludes NULL terminator
    char **pemChain)                    // Optional, MSCRYPT_free()
{
    const char *title = MSCRYPTP_VERIFY_CERT_TITLE;
    int ret = 0;
    int chainRet = 0;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    STACK_OF(X509) *chain = NULL;
    MSCRYPT_VERIFY_CERT_CTX *allocCtx = NULL;
    int pemRet = 1;

    *verifyChainError = 0;
    if (pemChainLength) {
        *pemChainLength = 0;
    } else {
        pemRet = 0;
    }
    if (pemChain) {
        *pemChain = NULL;
    } else {
        pemRet = 0;
    }

    ERR_clear_error();

    if (ctx == NULL) {
        allocCtx = MSCRYPT_create_verify_cert_ctx(NULL);
        if (allocCtx == NULL) {
            return 0;
        }

        ctx = allocCtx;
    }

    switch (certFormat) {
        case MSCRYPT_CERT_FORMAT_DER:
            ret = _der_cert_load(
                ctx->correlationId,
                certLength,
                certBytes,
                &cert);
            break;

        case MSCRYPT_CERT_FORMAT_PEM:
            ret = MSCRYPT_load_pem_cert(
                ctx->correlationId,
                certLength,
                certBytes,
                &cert,
                &ca);
            break;

        default:
            MSCRYPTP_trace_log_error(ctx->correlationId, 0, title, "CertFormat", "Not supported certificate format");
    }

    if (!ret) {
        goto end;
    }

    chainRet = MSCRYPT_verify_cert2(
        ctx,
        mscryptFlags,
        cert,
        ca,
        verifyChainError,
        pemRet ? &chain : NULL);
    if (chainRet == 0) {
        goto end;
    }

    if (pemRet) {
        ret = MSCRYPTP_pem_from_certs(
            ctx->correlationId,
            NULL,                   // X509 *cert
            chain,
            pemChainLength,
            pemChain);
    }

    if (ret) {
        ret = chainRet;
    }

end:
    X509_free(cert);
    sk_X509_pop_free(ca, X509_free);
    sk_X509_pop_free(chain, X509_free);
    MSCRYPT_free_verify_cert_ctx(allocCtx);
    return ret;
}

#ifndef MSCRYPT_TEST_WINDOWS

struct MSCRYPT_cert_dir_st {
    uuid_t      correlationId;
    DIR         *dir;               // closedir()
    char        *dirName;           // MSCRYPT_free()
    int         location;
};

static MSCRYPT_CERT_DIR *_open_trusted_cert_dir(
    const uuid_t correlationId,
    int mscryptFlags,
    int location)
{
    const char *title = MSCRYPTP_get_cert_ctrl_title(MSCRYPT_CERT_CTRL_ENUM, location);
    int ret = 0;
    MSCRYPT_CERT_DIR *certDir = NULL;           
    const char *dirName = NULL;                 // Don't free
    char *disallowedDirName = NULL;             // MSCRYPT_free()

    certDir = (MSCRYPT_CERT_DIR *) MSCRYPT_zalloc(sizeof(*certDir));
    if (certDir == NULL) {
        goto end;
    }

    if (correlationId == NULL) {
        RAND_bytes(certDir->correlationId, sizeof(certDir->correlationId));
    } else {
        memcpy(certDir->correlationId, correlationId, sizeof(certDir->correlationId));
    }

    certDir->location = location;

    if (location == MSCRYPT_CERT_LOCATION_DISALLOWED) {
        disallowedDirName = _get_disallowed_dir();
        if (disallowedDirName == NULL) {
            MSCRYPTP_trace_log_openssl_error(certDir->correlationId, 0, title, "_get_disallowed_dir");
            goto end;
        }
        dirName = disallowedDirName;
    } else {
        dirName = MSCRYPTP_get_default_cert_dir();
    }

    certDir->dirName = MSCRYPT_strdup(dirName);
    if (certDir->dirName == NULL) {
        goto end;
    }

    certDir->dir = opendir(dirName);
    if (certDir->dir == NULL) {
        int err = errno;
        MSCRYPTP_trace_log_errno_para(certDir->correlationId, 0, title, "opendir", err,
            "certDir: %s", dirName);
        goto end;
    }

    ret = 1;

end:
    MSCRYPT_free(disallowedDirName);
    if (!ret) {
        MSCRYPT_close_cert_dir(certDir);
        certDir = NULL;
    }
    return certDir;
}

// Returns directory handle or NULL on error.
MSCRYPT_CERT_DIR *MSCRYPT_open_trusted_cert_dir(
    const uuid_t correlationId,
    int mscryptFlags)
{
    return _open_trusted_cert_dir(correlationId, mscryptFlags, MSCRYPT_CERT_LOCATION_ROOT);
}

MSCRYPT_CERT_DIR *MSCRYPT_open_disallowed_cert_dir(
    const uuid_t correlationId,
    int mscryptFlags)
{
    return _open_trusted_cert_dir(correlationId, mscryptFlags, MSCRYPT_CERT_LOCATION_DISALLOWED);
}

// Return:
//  +1 - Success with *cert updated
//  -1 - No more certs. *cert is set to NULL.
//   0 - Error
int MSCRYPT_read_cert_dir(
    MSCRYPT_CERT_DIR *certDir,
    X509 **cert)                // X509_free()
{
    const char *title = MSCRYPTP_get_cert_ctrl_title(MSCRYPT_CERT_CTRL_ENUM, certDir->location);
    int ret = 0;
    const int asciiHexLength =
        certDir->location == MSCRYPT_CERT_LOCATION_DISALLOWED ? MSCRYPTP_MAX_FILENAME_HASH_LENGTH * 2 : 4 * 2;
    char *certPath = NULL;  // MSCRYPT_free()
    
    *cert = NULL;

    for(;;) {
        int nameLength = 0;
        int certPathLength = 0;
        int validName = 1;
        struct dirent *dp = NULL;
        BIO *in = NULL;

        errno = 0;
        dp = readdir(certDir->dir);

        if (dp == NULL) {
            int err = errno;

            if (err == 0) {
                ret = -1;
            } else {
                MSCRYPTP_trace_log_errno_para(certDir->correlationId, 0, title, "readdir", err,
                    "certDir: %s", certDir->dirName);
            }

            break;
        }

        // Skip "." and ".."
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0) {
            continue;
        }

        nameLength = (int) strlen(dp->d_name);
        certPathLength = (int) strlen(certDir->dirName) + 1 + nameLength + 1;
                
        MSCRYPT_free(certPath);
        certPath = (char *) MSCRYPT_zalloc(certPathLength);
        if (certPath == NULL) {
            break;
        }

        BIO_snprintf(certPath, certPathLength, "%s/%s",
            certDir->dirName, dp->d_name);

        // Skip files not matching 
        //  Trusted:      0b9a1734.0                            8 asciiHex "." digits "\0"
        //  Disallowed:   514be7009413c5cd96e99a33dc499f5d.0   32 asciiHex "." digits "\0"

        if (nameLength < asciiHexLength + 2 || dp->d_name[asciiHexLength] != '.') {
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

            for (int i = asciiHexLength + 1; i < nameLength; i++) {
                int c = dp->d_name[i];
                if (isdigit(c)) {
                    continue;
                }

                validName = 0;
                break;
            }
        }

        if (!validName) {
            MSCRYPTP_trace_log_para(certDir->correlationId, MSCRYPTP_TRACELOG_VERBOSE_FLAG, title, "Skipping file",
                "filename: %s", certPath);
            continue;
        }

        ERR_clear_error();

        in = BIO_new_file(certPath, "r");
        if (in == NULL) {
            MSCRYPTP_trace_log_openssl_error_para(certDir->correlationId, 0, title, "BIO_new_file",
                    "filename: %s", certPath);
            continue;
        }

        *cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
        BIO_free(in);

        if (*cert != NULL) {
            ret = 1;
            break;
        }

        MSCRYPTP_trace_log_openssl_error_para(certDir->correlationId, 0, title, "PEM_read_bio_X509_AUX",
            "filename: %s", certPath);
    }

    MSCRYPT_free(certPath);

    return ret;
}

void MSCRYPT_close_cert_dir(
    MSCRYPT_CERT_DIR *certDir)
{
    if (certDir != NULL) {
        if (certDir->dir != NULL) {
            closedir(certDir->dir);
        }
        MSCRYPT_free(certDir->dirName);
        MSCRYPT_free(certDir);
    }
}

#else

// Returns directory handle or NULL on error.
MSCRYPT_CERT_DIR *MSCRYPT_open_trusted_cert_dir(
    const uuid_t correlationId,
    int mscryptFlags)
{
    return NULL;
}

MSCRYPT_CERT_DIR *MSCRYPT_open_disallowed_cert_dir(
    const uuid_t correlationId,
    int mscryptFlags)
{
    return NULL;
}

// Return:
//  +1 - Success with *cert updated
//  -1 - No more certs. *cert is set to NULL.
//   0 - Error
int MSCRYPT_read_cert_dir(
    MSCRYPT_CERT_DIR *certDir,
    X509 **cert)                // X509_free()
{
    return 0;
}

void MSCRYPT_close_cert_dir(
    MSCRYPT_CERT_DIR *certDir)
{
}

#endif


