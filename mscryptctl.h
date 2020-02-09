#ifndef HEADER_MSCRYPTCTL_H
# define HEADER_MSCRYPTCTL_H


# include "mscrypt.h"
# include <openssl/bio.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct MSCRYPT_ctl_subject_st {
    ASN1_OCTET_STRING subjectIdentifier;    /* entry identifier */
    STACK_OF(X509_ATTRIBUTE) *attributes;   /* entry attributes: optional */
} MSCRYPT_CTL_SUBJECT;

typedef struct MSCRYPT_ctl_st {
    ASN1_INTEGER *version;                  /* version: defaults to v1(0) so may be NULL */
    STACK_OF(ASN1_OBJECT) *subjectUsages;   /* subject usages field */
    ASN1_OCTET_STRING *listIdentifier;      /* list identifier field: optional */
    ASN1_INTEGER *sequenceNumber;           /* sequence number field: optional */
    ASN1_TIME *thisUpdate;                  /* thisUpdate field */
    ASN1_TIME *nextUpdate;                  /* nextUpdate field: optional */
    X509_ALGOR subjectAlgorithm;            /* subject algorithm */
    STACK_OF(MSCRYPT_CTL_SUBJECT) *subjects;/* subject entries: optional */
    STACK_OF(X509_EXTENSION) *extensions;   /* extensions: optional */
} MSCRYPT_CTL;


DEFINE_STACK_OF(MSCRYPT_CTL_SUBJECT)
DEFINE_STACK_OF(MSCRYPT_CTL)

DECLARE_ASN1_FUNCTIONS(MSCRYPT_CTL_SUBJECT)
DECLARE_ASN1_FUNCTIONS(MSCRYPT_CTL)


//
// From wincrypt.h
//

//  Microsoft PKCS #7 ContentType Object Identifiers
#define szOID_CTL                       "1.3.6.1.4.1.311.10.1"

// CTL containing disallowed entries
#define szOID_DISALLOWED_LIST           "1.3.6.1.4.1.311.10.3.30"

// Use szOID_CERT_PROP_ID(CERT_SIGNATURE_HASH_PROP_ID) instead:
#define szOID_CERT_SIGNATURE_HASH_PROP_ID   "1.3.6.1.4.1.311.10.11.15"

// The CERT_SIGNATURE_HASH_PROP_ID and CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID
// properties are used for disallowed hashes.
#define szOID_DISALLOWED_HASH               szOID_CERT_SIGNATURE_HASH_PROP_ID

// MSCRYPT_CTL_free() returned CTL
MSCRYPT_CTL *MSCRYPT_CTL_parse(
    const uuid_t correlationId,
    int ctlLength,
    const unsigned char *ctlBytes);

// MSCRYPT_free() returned name
char *MSCRYPT_CTL_format_name(
    const uuid_t correlationId,
    MSCRYPT_CTL *ctl);


#ifdef  __cplusplus
}
#endif

#endif /* HEADER_MSCRYPTCTL_H */
