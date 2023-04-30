#ifndef TA_TEEencrypt_H
#define TA_TEEencrypt_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_UUID { 0x000eed46, 0x8e85, 0x49d7, { 0xba, 0x49, 0xbb, 0xb6, 0x4d, 0x7f, 0xca, 0x65} }

/* The function IDs implemented in this TA */
#define TA_TEEencrypt_CMD_ENC_VALUE	0
#define TA_TEEencrypt_CMD_DEC_VALUE	1
#define TA_TEEencrypt_CMD_RANDOMKEY_GET 2
#define TA_TEEencrypt_CMD_RANDOMKEY_ENC	3

#endif /*TA_HELLO_WORLD_H*/
