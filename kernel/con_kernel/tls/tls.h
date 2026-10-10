#ifndef KOSEC_TLS_H
#define KOSEC_TLS_H

//content type
enum {
    TLS_CT_CCS = 20, //change cipher spec
    TLS_CT_ALERT = 21, //alert
    TLS_CT_HANDSHAKE = 22, //handshake
    TLS_CT_APP_DATA = 23, //application data
};

//HandshakeType
enum {
    TLS_HT_HELLO_REQ = 0,
    TLS_HT_CLIENT_HELLO = 1,
    TLS_HT_SERVER_HELLO = 2,
    TLS_HT_NEW_SESSION_TICKET = 4,
    TLS_HT_CERTIFICATE = 11,
    TLS_HT_SERVER_KEY_EXCHANGE = 12,
    TLS_HT_CERTIFICATE_REQUEST = 13,
    TLS_HT_SERVER_HELLO_DONE = 14,
    TLS_HT_CERTIFICATE_VERIFY = 15,
    TLS_HT_CLIENT_KEY_EXCHANGE = 16,
    TLS_HT_FINISHED = 20,
    TLS_HT_CERTIFICATE_URL = 21, //CertificateURL, RFC6066
    TLS_HT_CERTIFICATE_STATUS = 22, //CertificateStatus,RFC6066
};

#define TLS_VERSION_MINOR(ver)	((ver) & 0xFF)
#define TLS_VERSION_MAJOR(ver)	(((ver) >> 8) & 0xFF)

#define TLS_VERSION_NUMBER(id)	((((id##_VERSION_MAJOR) & 0xFF) << 8) |	\
				 ((id##_VERSION_MINOR) & 0xFF))

#define TLS_1_2_VERSION_MAJOR	0x3
#define TLS_1_2_VERSION_MINOR	0x3
#define TLS_1_2_VERSION		TLS_VERSION_NUMBER(TLS_1_2)

#endif //endif KOSEC_TLS_H