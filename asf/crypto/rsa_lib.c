#include <stdio.h>
#include <string.h>
#include "rsa_def.h"
#include "alg_sha1.h"
#include "sec_cust_struct.h"
#include "sign_img.h"

/**************************************************************************
 *  MODULE NAME
 **************************************************************************/
#define MOD                         "AUTHEN"

/**************************************************************************
 *  EXTERNAL VARIABLE
 **************************************************************************/
extern unsigned char sha1sum[];
extern rsa_ctx rsa;
CUST_SEC_INTER g_cus_inter;

/**************************************************************************
 *  RSA SML KEY INIT
 **************************************************************************/
void lib_init_key(CUSTOMER_SEC_INTER cust_inter) {
    memcpy(&g_cus_inter, &cust_inter, 0x205);
    memset(&rsa, 0, sizeof(rsa));
    rsa.len = 0x80;
    bgn_read_str(&rsa.N, 0x10, g_cus_inter.key_rsa_n, 0x100);
    bgn_read_str(&rsa.E, 0x10, g_cus_inter.key_rsa_e, 5);
    bgn_read_str(&rsa.D, 0x10, g_cus_inter.key_rsa_d, rsa.len * 2);
    printf("[%s] rsa.N length = %d bytes\n", "AUTHEN", rsa.len * 8);
    printf("[%s] rsa.E length = %d bytes\n", "AUTHEN", 0x14);
}

/**************************************************************************
 *  SIGNING
 **************************************************************************/
int lib_sign(unsigned char *data_buf, unsigned int data_len, unsigned char *sig_buf, unsigned int sig_len) {
    int i = 0;

    if (RSA_KEY_LEN != sig_len) {
        printf("signature length is wrong (%d)\n", sig_len);
        goto _err;
    }

    /* hash the plain text */
    sha1(data_buf, data_len, sha1sum);

    /* encrypt the hash value (sign) */
    printf("[%s] RSA padding : RAW \n", MOD);
    if (rsa_sign(&rsa, HASH_LEN, sha1sum, sig_buf) != 0) {
        printf("failed\n");
        goto _err;
    }
    printf("[%s] sign image ... pass\n\n", MOD);

    /* output signature */
    printf("[%s] output signature: \n", MOD);
    printf(" ------------------------------------\n");
    for (i = 0; i < RSA_KEY_LEN; i++) {
        if (i == RSA_KEY_LEN - 1) {
            if (sig_buf[i] < 0x10) {
                printf("0x0%x", sig_buf[i]);
            } else {
                printf("0x%x", sig_buf[i]);
            }
        } else {
            if (sig_buf[i] < 0x10) {
                printf("0x0%x,", sig_buf[i]);
            } else {
                printf("0x%x,", sig_buf[i]);
            }
        }
    }
    printf("\n");

    /* self testing : verify this signature */
    printf("\n[%s] verify signature", MOD);
    if (rsa_verify(&rsa, HASH_LEN, sha1sum, sig_buf) != 0) {
        printf("failed\n");
        goto _err;
    }
    printf("... pass\n");

    return 0;

    _err:

    return -1;
}


/**************************************************************************
 *  HASHING
 **************************************************************************/
int lib_hash(unsigned char *data_buf, unsigned int data_len, unsigned char *hash_buf, unsigned int hash_len) {

    if (HASH_LEN != hash_len) {
        printf("hash length is wrong (%d)\n", hash_len);
        goto _err;
    }

    /* hash the plain text */
    sha1(data_buf, data_len, hash_buf);

    return 0;

    _err:

    return -1;

}


/**************************************************************************
 *  VERIFY SIGNATURE
 **************************************************************************/
int lib_verify(unsigned char *data_buf, unsigned int data_len, unsigned char *sig_buf, unsigned int sig_len) {

    if (RSA_KEY_LEN != sig_len) {
        printf("signature length is wrong (%d)\n", sig_len);
        goto _err;
    }

    printf("[%s] 0x%x,0x%x,0x%x,0x%x\n", MOD, data_buf[0], data_buf[1], data_buf[2], data_buf[3]);

    /* hash the plain text */
    sha1(data_buf, data_len, sha1sum);

    /* verify this signature */
    printf("[%s] verify signature", MOD);
    if (rsa_verify(&rsa, HASH_LEN, sha1sum, sig_buf) != 0) {
        printf(" ... failed\n");
        goto _err;
    }
    printf(" ... pass\n");

    return 0;

    _err:

    return -1;
}

