#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sign_img.h>
#include <sign_header.h>
#include <sign_extension.h>
#include <errno.h>

#include "lib_sign.h"
#include "sec_auth.h"
#include "sign_util.h"

/**************************************************************************
 *  DEFINITIONS
 **************************************************************************/
#define MOD                         "SignLib"
#define FB_SIG_EXT_NAME             ".sig"
#define FB_SIG_FILE_SIZE            256

/**************************************************************************
 *  MCARO
 **************************************************************************/
#define DBG                         printf


/**************************************************************************
 *  VARIABLES
 **************************************************************************/
SEC_CRYPTO_HASH_TYPE g_hash_type = SEC_CRYPTO_HASH_SHA1;
SEC_CRYPTO_SIGNATURE_TYPE g_sig_type = SEC_CRYPTO_SIG_RSA1024;
static unsigned int g_fb_chunk_size = 0x3200000; //set default to 50MB instead of 16MB due to lk default chunk change
#define FIX_FB_PADDING_HEADER_SIZE 0x4000 //default is 16KB

/**************************************************************************
 *  IMPORT KEY
 **************************************************************************/
int chk_img(char *img_name) {
    unsigned int br = 0;
    FILE *img_fd = fopen(img_name, "r");
    SEC_IMG_HEADER sec;

    if (img_fd == 0) {
        printf("[%s] %s not found\n", MOD, img_name);
        return -1;
    }

    br = fread((unsigned char *) &sec, 1, sizeof(SEC_IMG_HEADER), img_fd);

    if (br == 0) {
        printf("\n[%s] %s is empty\n", MOD, img_name);
        fclose(img_fd);
        return -2;
    }

    if (SEC_IMG_MAGIC == sec.magic_num) {
        printf("signed already (0x%x)\n", sec.magic_num);
        fclose(img_fd);
        return -3;
    }

    return 0;
}


/**************************************************************************
 *  IMPORT KEY
 **************************************************************************/
int imp_key(char *kf, char *kp, char gen_hdr, FILE *gen_fd) {
    CUSTOMER_SEC_INTER cust;
    unsigned char *r0, *r1, *r2;
    unsigned char line[300];

    /* ------------------------------------- */
    /* import key                            */
    /* ------------------------------------- */
    FILE *key_fd = fopen(kf, "r");
    if (key_fd == 0) {
        printf("[%s] %s not found\n", MOD, kf);
        return -1;
    } else {
        while (fgets(line, 300, key_fd) != NULL) {
            r0 = strtok(line, " ");
            r1 = strtok(NULL, " ");
            r2 = strtok(NULL, " \n");

            /* ------------------------------------- */
            /* parse key                             */
            /* ------------------------------------- */
            if (0 == memcmp(r0, CUSTOM_RSA_N, strlen(CUSTOM_RSA_N))) {
                printf("[%s] import CUSTOM_RSA_N\n", MOD);
                memcpy(cust.key_rsa_n, r2 + PREFIX_SIZE, sizeof(cust.key_rsa_n));

                /* ------------------------------------- */
                /* write key to generated header file    */
                /* ------------------------------------- */
                if (1 == gen_hdr) {
                    fwrite("#define ", 1, strlen("#define "), gen_fd);
                    fwrite(kp, 1, strlen(kp), gen_fd);
                    fwrite("_", 1, strlen("_"), gen_fd);
                    fwrite(CUSTOM_RSA_N, 1, strlen(CUSTOM_RSA_N), gen_fd);
                    fwrite(" \"", 1, strlen(" \""), gen_fd);
                    fwrite(cust.key_rsa_n, 1, sizeof(cust.key_rsa_n), gen_fd);
                    fwrite("\"\n", 1, strlen("\"\n"), gen_fd);
                }
            } else if (0 == memcmp(r0, CUSTOM_RSA_D, strlen(CUSTOM_RSA_D))) {
                printf("[%s] import CUSTOM_RSA_D\n", MOD);
                memcpy(cust.key_rsa_d, r2 + PREFIX_SIZE, sizeof(cust.key_rsa_d));
            } else if (0 == memcmp(r0, CUSTOM_RSA_E, strlen(CUSTOM_RSA_E))) {
                printf("[%s] import CUSTOM_RSA_E\n", MOD);
                memcpy(cust.key_rsa_e, r2 + PREFIX_SIZE, sizeof(cust.key_rsa_e));
                /* ------------------------------------- */
                /* write rsa key to generate header file */
                /* ------------------------------------- */
                if (1 == gen_hdr) {
                    fwrite("#define ", 1, strlen("#define "), gen_fd);
                    fwrite(kp, 1, strlen(kp), gen_fd);
                    fwrite("_", 1, strlen("_"), gen_fd);
                    fwrite(CUSTOM_RSA_E, 1, strlen(CUSTOM_RSA_E), gen_fd);
                    fwrite(" \"", 1, strlen(" \""), gen_fd);
                    fwrite(cust.key_rsa_e, 1, sizeof(cust.key_rsa_e), gen_fd);
                    fwrite("\"\n", 1, strlen("\"\n"), gen_fd);
                }
            } else {
                printf("[%s] %s format error\n", MOD, kf);
                return -1;
            }
        }
    }

    /* ------------------------------------- */
    /* initialize internal crypto engine     */
    /* ------------------------------------- */
    cust_init_key(cust.key_rsa_n, sizeof(cust.key_rsa_n),
                  cust.key_rsa_d, sizeof(cust.key_rsa_d),
                  cust.key_rsa_e, sizeof(cust.key_rsa_e));

    /* close key file */
    fclose(key_fd);

    return 0;
}

int imp_cfg(char *cfg_name, SEC_IMG_HEADER *sec) {
    unsigned char *r0, *r1, *r2;
    unsigned char line[300];
    unsigned int tmp, i;
    SEC_EXTENTION_CFG *p_ext_cfg = (SEC_EXTENTION_CFG *) get_ext_cfg();
    char b_ext_offset[MAX_VERITY_COUNT] = {0};
    char b_ext_length[MAX_VERITY_COUNT] = {0};
    unsigned int sign_hdr_version = 0;

    p_ext_cfg->chunk_size = SEC_CHUNK_SIZE_ZERO;

    /* ------------------------------------- */
    /* open image config file                */
    /* ------------------------------------- */
    FILE *config_fd = fopen(cfg_name, "r");

    if (config_fd == 0) {
        printf("[%s] %s not found\n", MOD, cfg_name);
        return -1;
    } else {
        while (fgets(line, 300, config_fd) != NULL) {
            r0 = strtok(line, " ");
            r1 = strtok(NULL, " ");
            r2 = strtok(NULL, " \n");

            /* ------------------------------------- */
            /* parse image config                    */
            /* ------------------------------------- */
            if (0 == memcmp(r0, CUSTOM_NAME, strlen(CUSTOM_NAME))) {
                if (0 == memcmp(r2, "NULL", strlen("NULL"))) {
                    printf("[%s] empty customer name '%s'\n", MOD, r2);
                    memset(sec->cust_name, 0, sizeof(sec->cust_name));
                } else
                    memcpy(sec->cust_name, r2, sizeof(sec->cust_name));
            } else if (0 == memcmp(r0, IMAGE_VERSION, strlen(IMAGE_VERSION)))
                sec->img_ver = atoi(r2);
            else if (0 == memcmp(r0, VERIFY_OFFSET, strlen(VERIFY_OFFSET))) {
                if (strlen(VERIFY_OFFSET) != strlen(r0)) {
                    sscanf(r0, "VERIFY_OFFSET[%u]", &tmp);
                    p_ext_cfg->verify_offset[tmp] = atoll(r2);
                    b_ext_offset[tmp] = 1;
                    printf("[%s] VERIFY_OFFSET[%d] = %lld\n", MOD, tmp, p_ext_cfg->verify_offset[tmp]);
                } else
                    sec->s_off = atoi(r2);
            } else if (0 == memcmp(r0, VERIFY_LENGTH, strlen(VERIFY_LENGTH))) {
                if (strlen(VERIFY_LENGTH) != strlen(r0)) {
                    sscanf(r0, "VERIFY_LENGTH[%u]", &tmp);
                    p_ext_cfg->verify_length[tmp] = atoll(r2);
                    b_ext_length[tmp] = 1;
                    printf("[%s] VERIFY_LENGTH[%d]=%lld\n", MOD, tmp, p_ext_cfg->verify_length[tmp]);
                } else
                    sec->s_len = atoi(r2);
            } else if (0 == memcmp(r0, VERIFY_COUNT, strlen(VERIFY_COUNT))) {
                p_ext_cfg->verify_count = atoi(r2);
                set_hdr_version(SEC_HDR_V3);
                printf("[%s] VERIFY_COUNT=%d\n", MOD, p_ext_cfg->verify_count);
            } else if (0 == memcmp(r0, CHUNK_SIZE, strlen(CHUNK_SIZE))) {
                p_ext_cfg->chunk_size = atoi(r2);
                printf("[%s] CHUNK_SIZE=%d\n", MOD, p_ext_cfg->chunk_size);
            } else if (0 == memcmp(r0, FB_CHUNK_SIZE, strlen(FB_CHUNK_SIZE))) {
                g_fb_chunk_size = atoi(r2);
                printf("[%s] FB_CHUNK_SIZE=%d\n", MOD, g_fb_chunk_size);
            } else if (0 == memcmp(r0, CFG_VERSION, strlen(CFG_VERSION))) {
                sign_hdr_version = atoi(r2);
                printf("[%s] CFG_VERSION=%d\n", MOD, sign_hdr_version);
            } else if (';' == r0[0]) {
                /* do nothing */
            } else if (NULL == r1) {
                /* do nothing */
            } else {
                printf("[%s] %s format error\n", MOD, cfg_name);
                fclose(config_fd);
                return -1;
            }
        }

        if (sign_hdr_version >= 4)
            set_hdr_version((SEC_IMG_HEADER_VER) (SEC_HDR_V1 + sign_hdr_version));

        /* check config format for v3 */
        if (is_hdr_version3() || is_hdr_version4()) {
            for (i = 0; i < p_ext_cfg->verify_count; i++) {
                if (!b_ext_offset[i] || !b_ext_length[i]) {
                    printf("[%s] %s config setting error\n", MOD, cfg_name);
                    fclose(config_fd);
                    return -1;
                }
            }
        }
    }

    return 0;
}

/**************************************************************************
 * WRITE IMAGE HEADER
 **************************************************************************/
int gen_hdr(char *cfg_name, char *hdr_name, char *img_name, char *hs_name) {
    SEC_IMG_HEADER sec = {0};
    SEC_IMG_HEADER_V4 sec_v4 = {0};
    int temp_file_fd;
    struct stat temp_file_stat;

    if (0 != imp_cfg(cfg_name, &sec))
        return -1;

    /* ------------------------------------- */
    /* fill and write header                 */
    /* ------------------------------------- */
    FILE *hdr_fd = fopen(hdr_name, "wb");

    /* config common part */
    FILE *img_fd = fopen(img_name, "r");
    if (img_fd == 0) {
        printf("[%s] %s not found\n", MOD, img_name);
        goto img_err;
    }

    temp_file_fd = fileno(img_fd);
    fstat(temp_file_fd, &temp_file_stat);

    if (is_hdr_version4()) {
        sec_v4.magic_num = SEC_IMG_MAGIC;
        memcpy(sec_v4.cust_name, sec.cust_name, sizeof(sec.cust_name));
        sec_v4.image_verion = sec.img_ver;
        sec_v4.image_offset = SEC_IMG_HDR_SZ;
        sec_v4.image_length_high = ((temp_file_stat.st_size & 0xFFFFFFFF00000000ULL) >> 32) & 0x00000000FFFFFFFFULL;
        sec_v4.image_length_low = (long long) temp_file_stat.st_size & 0x00000000FFFFFFFFULL;
        printf("[%s] size of '%s' is '0x%lx'\n", MOD, img_name, temp_file_stat.st_size);
        printf("[%s] size of '%s' is '0x%lx' (0x%x, 0x%x)\n", MOD, img_name, temp_file_stat.st_size,
               sec_v4.image_length_high, sec_v4.image_length_low);
    } else {
        sec.img_len = temp_file_stat.st_size;
        printf("[%s] size of '%s' is '0x%x'\n", MOD, img_name, sec.img_len);
        sec.magic_num = SEC_IMG_MAGIC;
        sec.img_off = SEC_IMG_HDR_SZ;
        sec.sig_off = sec.img_off + sec.img_len;
    }

    fclose(img_fd);

    if (is_hdr_version4()) {
        SEC_EXTENTION_CFG *p_ext_cfg = (SEC_EXTENTION_CFG *) get_ext_cfg();
        unsigned long long img_length = sec_v4.image_length_high;
        img_length = (img_length << 32) & 0xFFFFFFFF00000000ULL;
        img_length += sec_v4.image_length_low;

        sec_v4.signature_length = get_sigature_size(g_sig_type) + get_hash_size(g_hash_type);
        sec_v4.ext_magic = SEC_EXTENSION_MAGIC_V4;
        sec_v4.ext_hdr_length = 0;

        /* config header for v4 */
        if (config_header_v3_chk(img_length))
            goto check_err;

        /* ------------------------------------- */
        /* write to image                        */
        /* ------------------------------------- */
        fwrite(&sec_v4, 1, sizeof(sec_v4), hdr_fd);

        /* ------------------------------------- */
        /* dump information                      */
        /* ------------------------------------- */
        printf("[%s] hdr_v4.magic_num        = 0x%x\n", MOD, sec_v4.magic_num);
        printf("[%s] hdr_v4.cust_name        = %s\n", MOD, sec_v4.cust_name);
        printf("[%s] hdr_v4.image_verion     = %d (0x%x)\n", MOD, sec_v4.image_verion, sec_v4.image_verion);
        printf("[%s] hdr_v4.signature_length = %d (0x%x)\n", MOD, sec_v4.signature_length, sec_v4.signature_length);
        printf("[%s] hdr_v4.image_offset     = %d (0x%x)\n", MOD, sec_v4.image_offset, sec_v4.image_offset);
        printf("[%s] hdr_v4.ext_magic        = %d (0x%x)\n", MOD, sec_v4.ext_magic, sec_v4.ext_magic);
        printf("[%s] hdr_v4.ext_hdr_length   = %d (0x%x)\n", MOD, sec_v4.ext_hdr_length, sec_v4.ext_hdr_length);
        printf("[%s] hdr_v4.image_length     = %lld (0x%llx)\n", MOD, img_length, img_length);
    } else {
        if (is_hdr_version3()) {
            unsigned long long img_length = sec.img_len & 0xFFFFFFFFULL;

            sec.sig_len = get_sigature_size(g_sig_type) + get_hash_size(g_hash_type);

            sec.s_off = SEC_EXTENSION_MAGIC;
            sec.s_len = SEC_EXTENSION_MAGIC;

            /* config header for v3 */
            if (config_header_v3_chk(img_length))
                goto check_err;
        } else {
            /* config header for v1 and v2 */
            if (config_header_v1_v2_chk(&sec))
                goto check_err;
        }
        /* ------------------------------------- */
        /* write to image                        */
        /* ------------------------------------- */
        fwrite(&sec, 1, sizeof(sec), hdr_fd);

        /* ------------------------------------- */
        /* dump information                      */
        /* ------------------------------------- */
        printf("[%s] hdr.magic_num = 0x%x\n", MOD, sec.magic_num);
        printf("[%s] hdr.cust_name = %s\n", MOD, sec.cust_name);
        printf("[%s] hdr.img_ver   = %d (0x%x)\n", MOD, sec.img_ver, sec.img_ver);
        printf("[%s] hdr.img_len   = %d (0x%x)\n", MOD, sec.img_len, sec.img_len);
        printf("[%s] hdr.img_off   = %d (0x%x)\n", MOD, sec.img_off, sec.img_off);
        printf("[%s] hdr.s_off     = %d (0x%x)\n", MOD, sec.s_off, sec.s_off);
        printf("[%s] hdr.s_len     = %d (0x%x)\n", MOD, sec.s_len, sec.s_len);
        printf("[%s] hdr.sig_off   = %d (0x%x)\n", MOD, sec.sig_off, sec.sig_off);
        printf("[%s] hdr.sig_len   = %d (0x%x)\n", MOD, sec.sig_len, sec.sig_len);
    }

    img_err:
    check_err:
    /* close header file */
    fclose(hdr_fd);

    return 0;
}


/**************************************************************************
 * WRITE HASH + SIGNATURE
 **************************************************************************/

int pro_img_v1_v2(char *hs_name, char *img_name, char *hdr_name) {
    unsigned int br = 0;
    unsigned char *d_buf = NULL;
    unsigned char c_buf[SEC_IMG_HDR_SZ];
    unsigned char *sig;
    unsigned char *hash;
    unsigned int i = 0;
    SEC_IMG_HEADER *sec = NULL;

    /* ------------------------------------- */
    /* open hash and signature file          */
    /* ------------------------------------- */
    FILE *hs_fd = fopen(hs_name, "wb");

    if (hs_fd == 0) {
        printf("[%s] %s not found\n", MOD, hs_name);
        goto _err;
    }

    /* ------------------------------------- */
    /* read image header                     */
    /* ------------------------------------- */

    FILE *hdr_fd = fopen(hdr_name, "r");

    br = fread(c_buf, 1, SEC_IMG_HDR_SZ, hdr_fd); /* read header */
    sec = (SEC_IMG_HEADER *) c_buf;

    if (br == 0) {
        printf("\n[%s] read '%s' image hdr fail,  read bytes = '%d'\n", MOD, hdr_name, br);
        goto _err;
    }


    /* ------------------------------------- */
    /* initialize buffer                     */
    /* ------------------------------------- */
    d_buf = (unsigned char *) malloc(SEC_IMG_HDR_SZ + sec->s_len * sizeof(char));
    sig = (unsigned char *) malloc(get_sigature_size(g_sig_type));
    hash = (unsigned char *) malloc(get_hash_size(g_hash_type));

    memcpy(d_buf, c_buf, SEC_IMG_HDR_SZ);

    /* ------------------------------------- */
    /* read image content                    */
    /* ------------------------------------- */
    FILE *img_fd = fopen(img_name, "r");

    if (img_fd == 0) {
        printf("[%s] %s not found\n", MOD, img_name);
        goto _err;
    }

    fseeko(img_fd, sec->s_off * sizeof(char), SEEK_SET);

    br = fread(d_buf + SEC_IMG_HDR_SZ, 1, sec->s_len, img_fd);

    if (br == 0) {
        printf("\n[%s] read image content fail, read bytes = '%d'\n", MOD, br);
        goto _err;
    }

    /* ------------------------------------- */
    /* Sign
     * @1 : file
     * @2 : file length to be signed
     * @3 : signature
     * @3 : signature length */
    /* ------------------------------------- */
    if (cust_sign(d_buf, SEC_IMG_HDR_SZ + sec->s_len, sig, get_sigature_size(g_sig_type)) == -1) {
        printf("[%s] Sign %s fail\n", MOD, img_name);
        goto _err;
    }

    /* ------------------------------------- */
    /* Hash
     * @1 : file
     * @2 : file length to be hashed
     * @3 : hash
     * @3 : hash length */
    /* ------------------------------------- */
    if (cust_hash(d_buf, SEC_IMG_HDR_SZ + sec->s_len, hash, get_hash_size(g_hash_type)) == -1) {
        printf("[%s] Sign %s fail\n", MOD, img_name);
        goto _err;
    }

    /* ------------------------------------- */
    /* dump hash value for debug             */
    /* ------------------------------------- */
    printf("[%s] Hash value :\n", MOD);
    for (i = 0; i < get_hash_size(g_hash_type); i++)
        printf("0x%x,", hash[i]);
    printf("\n");

    /* ------------------------------------- */
    /* write hash and signature              */
    /* ------------------------------------- */
    fwrite(sig, 1, get_sigature_size(g_sig_type), hs_fd);
    fwrite(hash, 1, get_hash_size(g_hash_type), hs_fd);
    fclose(hs_fd);

    free(d_buf);
    return 0;

    _err:

    free(d_buf);
    return -1;

}

#define DUMP_MORE_FOR_DEBUG 0

static int gen_hash_by_chunk(FILE *img_fd, unsigned long long img_hash_off, unsigned long long img_hash_len,
                             unsigned char *final_hash_buf, SEC_CRYPTO_HASH_TYPE hash_type, unsigned int chunk_size) {
    unsigned int br = 0;
    unsigned int i = 0, ret = 0;
    unsigned char *chunk_buf = NULL;
    unsigned char *hash_tmp;
    unsigned char *hash_comb;
    unsigned long long seek_pos = 0;
    unsigned int hash_size = get_hash_size(hash_type);
    unsigned long long chunk_count = ((img_hash_len - 1) / chunk_size) + 1;
    unsigned int read_size = 0;
    unsigned long long left_size = 0;

    if (!img_hash_len) {
        printf("[%s] hash length is zero, no need to do hash\n", MOD);
        ret = -1;
        memset(final_hash_buf, 0x00, hash_size);
        goto end_error;
    }

#if DUMP_MORE_FOR_DEBUG
    DBG("[%s] Hash size is %d (0x%x)\n", MOD, hash_size, hash_size);
    DBG("[%s] Offset is %lld (0x%llx)\n", MOD, img_hash_off, img_hash_off);
    DBG("[%s] Size is %lld (0x%llx)\n", MOD, img_hash_len, img_hash_len);
    DBG("[%s] Chunk size is %d (0x%x)\n", MOD, chunk_size, chunk_size);
    DBG("[%s] Chunk count is %lld (0x%llx)\n", MOD, chunk_count, chunk_count);
#endif

    /* allocate hash buffer */
    hash_tmp = (unsigned char *) malloc(hash_size);
    hash_comb = (unsigned char *) malloc(hash_size * 2);
    memset(hash_tmp, 0x00, hash_size);
    memset(hash_comb, 0x00, hash_size * 2);

    /* allocate buffer with known chunk size */
    chunk_buf = (unsigned char *) malloc(chunk_size);

    /* caculate first hash */
    seek_pos = img_hash_off;
    left_size = img_hash_len;
    read_size = (left_size >= chunk_size) ? chunk_size : left_size;
    fseeko(img_fd, seek_pos * sizeof(char), SEEK_SET);

    br = fread(chunk_buf, 1, read_size, img_fd);
    if (br != read_size) {
        printf("[%s] read image content fail, read offset = '0x%llx'\n", MOD, seek_pos);
        ret = -2;
        goto end_error;
    }

    if (cust_hash(chunk_buf, read_size, hash_tmp, hash_size) == -1) {
        printf("[%s] hash fail, offset is '0x%llx'(A)\n", MOD, seek_pos);
        ret = -3;
        goto end_error;
    }

#if DUMP_MORE_FOR_DEBUG
    /* ------------------------------------- */
    /* dump hash value for debug             */
    /* ------------------------------------- */
    DBG("[%s] Data value(4 bytes) ==> (0x%x, 0x%x, 0x%x, 0x%x) \n", MOD,
            chunk_buf[0], chunk_buf[1], chunk_buf[2], chunk_buf[3]);
    DBG("[%s] Hash value(single) (0x%llx): \n", MOD, seek_pos);
    for (i = 0; i < hash_size; i++)
        DBG("0x%x,", hash_tmp[i]);
    DBG("\n", MOD);
#endif

    /* copy to compose buffer (first block) */
    memcpy(hash_comb, hash_tmp, hash_size);

    /* move next */
    seek_pos += read_size;
    left_size -= read_size;

    /* loop hash */
    while (left_size) {
        /* load data */
        read_size = (left_size >= chunk_size) ? chunk_size : left_size;
        fseeko(img_fd, seek_pos * sizeof(char), SEEK_SET);
        br = fread(chunk_buf, 1, read_size, img_fd);

        if (br != read_size) {
            printf("[%s] read image content fail, read offset = '0x%llx'\n", MOD, seek_pos);
            ret = -4;
            goto end_error;
        }

        /* caculate this hash */
        if (cust_hash(chunk_buf, read_size, hash_tmp, hash_size) == -1) {
            printf("[%s] hash fail, offset is '0x%llx'(B)\n", MOD, seek_pos);
            ret = -5;
            goto end_error;
        }

#if DUMP_MORE_FOR_DEBUG
        /* ------------------------------------- */
        /* dump hash value for debug             */
        /* ------------------------------------- */
        DBG("[%s] Data value(4 bytes) ==> (0x%x, 0x%x, 0x%x, 0x%x)\n", MOD,
                chunk_buf[0], chunk_buf[1], chunk_buf[2], chunk_buf[3]);
        DBG("[%s] Hash value(single) (0x%llx):\n", MOD, seek_pos);
        for (i = 0; i < hash_size; i++)
            DBG("0x%x,", hash_tmp[i]);
        DBG("\n");
#endif

        /* compose two hash to buffer (second block) */
        memcpy(hash_comb + hash_size, hash_tmp, hash_size);

        /* caculate compose hash */
        if (cust_hash(hash_comb, hash_size * 2, hash_tmp, hash_size) == -1) {
            printf("[%s] hash fail, offset is '0x%llx'(C)\n", MOD, seek_pos);
            ret = -6;
            goto end_error;
        }

#if DUMP_MORE_FOR_DEBUG
        /* ------------------------------------- */
        /* dump hash value for debug             */
        /* ------------------------------------- */
        DBG("[%s] Data value(4 bytes) ==> (0x%x, 0x%x, 0x%x, 0x%x)\n", MOD,
                hash_comb[0], hash_comb[1], hash_comb[2], hash_comb[3]);
        DBG("[%s] Hash value(comp): \n", MOD);
        for (i = 0; i < hash_size; i++)
            DBG("0x%x,", hash_tmp[i]);
        DBG("\n");
#endif

        /* save this hash to compose buffer (first block) */
        memcpy(hash_comb, hash_tmp, hash_size);

        /* move next */
        seek_pos += read_size;
        left_size -= read_size;
    }

    /* ------------------------------------- */
    /* dump hash value for debug             */
    /* ------------------------------------- */
#if DUMP_MORE_FOR_DEBUG
    DBG("[%s] Hash value(final) :\n", MOD);
    for (i = 0; i < hash_size; i++)
        DBG("0x%x,", hash_tmp[i]);
    DBG("\n");
#endif

    /* copy hash */
    memcpy(final_hash_buf, hash_tmp, hash_size);

    end_error:
    free(hash_comb);
    free(chunk_buf);
    free(hash_tmp);

    return ret;
}

int pro_img_v3_v4(char *hs_name, char *img_name, char *hdr_name) {
    unsigned int br = 0;
    unsigned char *d_buf = NULL;
    unsigned char *d_buf_prt = NULL;
    unsigned char c_buf[SEC_IMG_HDR_SZ];
    unsigned char *sig;
    unsigned char *hash;
    unsigned int i = 0, ret = 0;
    SEC_EXTENTION_CFG *p_ext_cfg = (SEC_EXTENTION_CFG *) get_ext_cfg();
    SEC_EXTENSTION_CRYPTO *crypto_ext = NULL;
    SEC_FRAGMENT_CFG *frag_ext = NULL;
    SEC_EXTENSTION_HASH_ONLY **hash_only_ext;
    SEC_EXTENSTION_HASH_ONLY_64 **hash_only_ext_64;
    SEC_EXTENSTION_END_MARK *end_ext = NULL;
    unsigned int total_size = 0;
    unsigned int real_chunk_size = 0;

    /* ------------------------------------- */
    /* open hash and signature file          */
    /* ------------------------------------- */
    FILE *hs_fd = fopen(hs_name, "wb");

    if (hs_fd == 0) {
        printf("[%s] %s not found\n", MOD, hs_name);
        goto _init_fail;
    }

    /* ------------------------------------- */
    /* read image header                     */
    /* ------------------------------------- */

    FILE *hdr_fd = fopen(hdr_name, "r");

    br = fread(c_buf, 1, SEC_IMG_HDR_SZ, hdr_fd); /* read header */

    if (br == 0) {
        printf("\n[%s] read '%s' image hdr fail, read bytes = '%d'\n", MOD, hdr_name, br);
        ret = -1;
        goto _hdr_fail;
    }

    /* ------------------------------------- */
    /* initialize buffer                     */
    /* ------------------------------------- */
    sig = (unsigned char *) malloc(get_sigature_size(g_sig_type));
    hash = (unsigned char *) malloc(get_hash_size(g_hash_type));

    /* ------------------------------------- */
    /* initialize extnesion header buffer       */
    /* ------------------------------------- */
    crypto_ext = (SEC_EXTENSTION_CRYPTO *) allocate_ext_crypto();
    frag_ext = (SEC_FRAGMENT_CFG *) allocate_ext_frag();

    if (is_hdr_version4()) {
        hash_only_ext_64 = (SEC_EXTENSTION_HASH_ONLY_64 **) malloc(
                p_ext_cfg->verify_count * sizeof(SEC_EXTENSTION_HASH_ONLY_64 *));
        for (i = 0; i < p_ext_cfg->verify_count; i++)
            hash_only_ext_64[i] = (SEC_EXTENSTION_HASH_ONLY_64 *) allocate_ext_hash_only_64(g_hash_type);
    } else {
        hash_only_ext = (SEC_EXTENSTION_HASH_ONLY **) malloc(
                p_ext_cfg->verify_count * sizeof(SEC_EXTENSTION_HASH_ONLY *));
        for (i = 0; i < p_ext_cfg->verify_count; i++)
            hash_only_ext[i] = (SEC_EXTENSTION_HASH_ONLY *) allocate_ext_hash_only(g_hash_type);
    }

    end_ext = (SEC_EXTENSTION_END_MARK *) allocate_ext_end();

    /* ------------------------------------- */
    /* initial extenstion header             */
    /* ------------------------------------- */
    crypto_ext->hash_type = g_hash_type;
    crypto_ext->sig_type = g_sig_type;
    crypto_ext->enc_type = SEC_CRYPTO_ENC_UNKNOWN;
    frag_ext->frag_count = p_ext_cfg->verify_count;
    frag_ext->chunk_size = p_ext_cfg->chunk_size;
    if (is_hdr_version4()) {
        for (i = 0; i < p_ext_cfg->verify_count; i++) {
            hash_only_ext_64[i]->hash_offset_64 = p_ext_cfg->verify_offset[i];
            hash_only_ext_64[i]->hash_len_64 = p_ext_cfg->verify_length[i];
        }
    } else {
        for (i = 0; i < p_ext_cfg->verify_count; i++) {
            hash_only_ext[i]->hash_offset = p_ext_cfg->verify_offset[i];
            hash_only_ext[i]->hash_len = p_ext_cfg->verify_length[i];
        }
    }

    /* ----------------------------------------- */
    /* generate hash for each region by chunk size      */
    /* ----------------------------------------- */
    FILE *img_fd = fopen(img_name, "r");

    if (img_fd == 0) {
        printf("[%s] %s not found\n", MOD, img_name);
        ret = -1;
        goto _img_open_fail;
    }

    for (i = 0; i < p_ext_cfg->verify_count; i++) {
        if (is_hdr_version4()) {
            if (frag_ext->chunk_size == 0)
                real_chunk_size = hash_only_ext_64[i]->hash_len_64;
            else
                real_chunk_size = frag_ext->chunk_size;

            if (gen_hash_by_chunk(img_fd, hash_only_ext_64[i]->hash_offset_64, hash_only_ext_64[i]->hash_len_64,
                                  hash, hash_only_ext_64[i]->sub_type, real_chunk_size) != 0) {
                ret = -1;
                goto _ext_hash_fail;
            }
            memcpy(hash_only_ext_64[i]->hash_data, hash, get_hash_size(g_hash_type));
        } else {
            if (frag_ext->chunk_size == 0)
                real_chunk_size = hash_only_ext[i]->hash_len;
            else
                real_chunk_size = frag_ext->chunk_size;

            if (gen_hash_by_chunk(img_fd, hash_only_ext[i]->hash_offset, hash_only_ext[i]->hash_len,
                                  hash, hash_only_ext[i]->sub_type, real_chunk_size) != 0) {
                ret = -1;
                goto _ext_hash_fail;
            }
            memcpy(hash_only_ext[i]->hash_data, hash, get_hash_size(g_hash_type));
        }
    }

    /* ------------------------------------- */
    /* prepare buffer                     */
    /* ------------------------------------- */
    total_size = SEC_IMG_HDR_SZ +
                 p_ext_cfg->verify_count * get_hash_size(g_hash_type) +
                 sizeof(*crypto_ext) +
                 sizeof(*frag_ext) +
                 sizeof(*end_ext);

    if (is_hdr_version4())
        total_size += p_ext_cfg->verify_count * get_ext_hash_only_64_struct_size(g_hash_type);
    else
        total_size += p_ext_cfg->verify_count * get_ext_hash_only_struct_size(g_hash_type);

    d_buf = (unsigned char *) malloc(total_size);
    d_buf_prt = d_buf;

    /* copy header */
    memcpy(d_buf_prt, c_buf, SEC_IMG_HDR_SZ);
    d_buf_prt += SEC_IMG_HDR_SZ;

    /* copy hash */
    for (i = 0; i < p_ext_cfg->verify_count; i++) {
        if (is_hdr_version4())
            memcpy(d_buf_prt, hash_only_ext_64[i]->hash_data, get_hash_size(g_hash_type));
        else
            memcpy(d_buf_prt, hash_only_ext[i]->hash_data, get_hash_size(g_hash_type));

        d_buf_prt += get_hash_size(g_hash_type);
    }

    /* copy crypto extension */
    memcpy(d_buf_prt, crypto_ext, sizeof(*crypto_ext));
    d_buf_prt += sizeof(*crypto_ext);

    /* copy frag extension */
    memcpy(d_buf_prt, frag_ext, sizeof(*frag_ext));
    d_buf_prt += sizeof(*frag_ext);

    /* copy hash extension */
    for (i = 0; i < p_ext_cfg->verify_count; i++) {
        if (is_hdr_version4()) {
            memcpy(d_buf_prt, hash_only_ext_64[i], get_ext_hash_only_64_struct_size(g_hash_type));
            d_buf_prt += get_ext_hash_only_64_struct_size(g_hash_type);
        } else {
            memcpy(d_buf_prt, hash_only_ext[i], get_ext_hash_only_struct_size(g_hash_type));
            d_buf_prt += get_ext_hash_only_struct_size(g_hash_type);
        }
    }

    /* copy end mark extension */
    memcpy(d_buf_prt, end_ext, sizeof(*end_ext));
    d_buf_prt += sizeof(*end_ext);

    /* ------------------------------------- */
    /* generate hash                    */
    /* ------------------------------------- */
    if (cust_hash(d_buf, total_size, hash, get_hash_size(g_hash_type)) == -1) {
        printf("[%s] Sign %s fail\n", MOD, img_name);
        ret = -1;
        goto _final_hash_fail;
    }

    /* ------------------------------------- */
    /* generate signature                    */
    /* ------------------------------------- */
    if (cust_sign(d_buf, total_size, sig, get_sigature_size(g_sig_type)) == -1) {
        printf("[%s] Sign %s fail\n", MOD, img_name);
        ret = -1;
        goto _final_sign_fail;
    }

    /* ------------------------------------- */
    /* dump hash value for debug             */
    /* ------------------------------------- */
#if DUMP_MORE_FOR_DEBUG
    {
        unsigned loop_count = total_size / 8;
        unsigned remain_count = total_size % 8;
        printf("[%s] Total verify size is : %d\n", MOD, total_size);
        for (i = 0; i < loop_count; i++) {
            DBG("[%s] Data value [%d-%d]==> (0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x) \n", MOD,
                    i * 8, (i + 1) * 8 - 1,
                    d_buf[0 + i * 8], d_buf[1 + i * 8], d_buf[2 + i * 8], d_buf[3 + i * 8],
                    d_buf[4 + i * 8], d_buf[5 + i * 8], d_buf[6 + i * 8], d_buf[7 + i * 8]);
        }

        if (remain_count) {
            DBG("[%s] Data value [%d-%d]==> (", MOD, loop_count * 8, loop_count * 8 + remain_count);
            for (i = 0; i < remain_count; i++)
                DBG("0x%x,", d_buf[loop_count * 8 + i]);
            DBG(")\n");
        }
    }
#endif
    printf("[%s] Hash value :\n", MOD);
    for (i = 0; i < get_hash_size(g_hash_type); i++)
        printf("0x%x,", hash[i]);
    printf("\n");

    /* ------------------------------------- */
    /* write hash and signature              */
    /* ------------------------------------- */
    fwrite(sig, 1, get_sigature_size(g_sig_type), hs_fd);
    fwrite(hash, 1, get_hash_size(g_hash_type), hs_fd);

    /* ------------------------------------- */
    /* write extension              */
    /* ------------------------------------- */
    d_buf_prt = d_buf;
    d_buf_prt += SEC_IMG_HDR_SZ + p_ext_cfg->verify_count * get_hash_size(g_hash_type);
    fwrite(d_buf_prt, 1,
           total_size - (SEC_IMG_HDR_SZ + p_ext_cfg->verify_count * get_hash_size(g_hash_type)),
           hs_fd);

    fclose(hs_fd);

    _final_sign_fail:
    _final_hash_fail:
    free(d_buf);
    _ext_hash_fail:
    _img_open_fail:
    _img_read_fail:
    free(end_ext);

    free(frag_ext);
    free(crypto_ext);

    if (is_hdr_version4())
        free(hash_only_ext_64);
    else
        free(hash_only_ext);

    free(hash);
    free(sig);
    _hdr_fail:
    fclose(hdr_fd);
    _init_fail:

    return ret;
}

int pro_img(char *hs_name, char *img_name, char *hdr_name) {
    if (is_hdr_version3() || is_hdr_version4())
        return pro_img_v3_v4(hs_name, img_name, hdr_name);
    else
        return pro_img_v1_v2(hs_name, img_name, hdr_name);
}

#define DUMP_FB_FOR_DEBUG 0

int pro_fb_sig(char *input_img, char *cfg_name, char *output_hdr, char *original_img_name) {
    unsigned int i = 0, ret = 0;
    char output_file[256] = {0};
    unsigned int input_len = 0;
    unsigned int last_slash_pot = 0;
    unsigned int last_underscore_pot = 0;
    SEC_IMG_HEADER sec = {0};
    SEC_FB_HEADER fb_hdr = {0};
    SEC_FB_HEADER_V2 fb_hdr_v2 = {0};
    unsigned char *fb_chunk_buffer = NULL;
    unsigned char *fb_multiple_hash_buffer = NULL;
    unsigned char *fb_signature_file_buffer = NULL;
    unsigned char *fb_pad_hdr_file_buffer = NULL;
    unsigned int fb_chunk_count = 0;
    unsigned int fb_multiple_hash_buffer_len = 0;
    unsigned int hash_size = get_hash_size(g_hash_type);
    unsigned int sig_size = get_sigature_size(g_sig_type);
    unsigned char *sig_buf = NULL;
    unsigned char *hash_buf = NULL;
    unsigned long long left_size = 0;
    unsigned int read_size = 0;
    unsigned long long seek_pos = 0;
    unsigned int br = 0;
    unsigned int current_chunk_count = 0;
    int temp_file_fd;
    struct stat temp_file_stat;
    unsigned long long input_img_length = 0;

    /* ------------------------------------- */
    /* generate the output file name from input_img file name */
    /* ------------------------------------- */
    input_len = strlen(input_img);

    for (i = 0; i < input_len; i++) {
        if (input_img[i] == '/')
            last_slash_pot = i;

        if (input_img[i] == '-')
            last_underscore_pot = i;
    }

    memcpy(output_file, input_img, input_len);
    memcpy(output_file + input_len, FB_SIG_EXT_NAME, strlen(FB_SIG_EXT_NAME));

    printf("[%s] Signed file path is '%s'\n", MOD, input_img);
    printf("[%s] FB SIG path is '%s'\n", MOD, output_file);


    /* ------------------------------------- */
    /* get the image config from config file */
    /* ------------------------------------- */
    if (0 != imp_cfg(cfg_name, &sec))
        return -1;

    /* ------------------------------------- */
    /* get the original image length from original_img_name */
    /* ------------------------------------- */
    FILE *orig_img_fd = fopen(original_img_name, "r");
    if (orig_img_fd == 0) {
        printf("[%s] %s not found\n", MOD, original_img_name);
        ret = -2;
        goto orig_img_err;
    }
    temp_file_fd = fileno(orig_img_fd);
    fstat(temp_file_fd, &temp_file_stat);
    if (is_hdr_version4()) {
        fb_hdr_v2.orig_img_size_64 = temp_file_stat.st_size;
        printf("[%s] size of '%s' is '0x%llx'\n", MOD, original_img_name, fb_hdr_v2.orig_img_size_64);
    } else {
        fb_hdr.orig_img_size = temp_file_stat.st_size;
        printf("[%s] size of '%s' is '0x%x'\n", MOD, original_img_name, fb_hdr.orig_img_size);
    }
    fclose(orig_img_fd);

    /* ------------------------------------- */
    /* get the image length from input_img */
    /* ------------------------------------- */
    FILE *img_fd = fopen(input_img, "r");
    if (img_fd == 0) {
        printf("[%s] %s not found\n", MOD, input_img);
        ret = -2;
        goto input_img_err;
    }
    temp_file_fd = fileno(img_fd);
    fstat(temp_file_fd, &temp_file_stat);
    input_img_length = temp_file_stat.st_size;
    printf("[%s] size of '%s' is '0x%llx'\n", MOD, input_img, input_img_length);

    /* ------------------------------------- */
    /* reset for fb header */
    /* ------------------------------------- */
    sec.magic_num = FB_IMG_MAGIC;

    printf("[%s] sec.magic_num = 0x%x\n", MOD, sec.magic_num);
    printf("[%s] sec.cust_name = %s\n", MOD, sec.cust_name);
    printf("[%s] sec.img_ver   = %d (0x%x)\n", MOD, sec.img_ver, sec.img_ver);
    printf("[%s] sec.img_len   = %lld (0x%llx)\n", MOD, input_img_length, input_img_length);
    if (is_hdr_version4()) {
        fb_hdr_v2.magic_num = FB_IMG_MAGIC;
        fb_hdr_v2.hdr_ver = 0x02;
        fb_hdr_v2.chunk_size = g_fb_chunk_size;

        if (input_img_length <= (g_fb_chunk_size - FIX_FB_PADDING_HEADER_SIZE))
            fb_hdr_v2.hash_count = 1;
        else
            fb_hdr_v2.hash_count =
                    ((input_img_length - (g_fb_chunk_size - FIX_FB_PADDING_HEADER_SIZE) - 1) / g_fb_chunk_size) + 1 + 1;

        fb_chunk_count = fb_hdr_v2.hash_count;
        memcpy(fb_hdr_v2.part_name, input_img + last_slash_pot + 1, last_underscore_pot - last_slash_pot - 1);

        /* ------------------------------------- */
        /* dump information */
        /* ------------------------------------- */
        printf("[%s] fb_hdr_v2.magic_num        = %d (0x%x)\n", MOD, fb_hdr_v2.magic_num, fb_hdr_v2.magic_num);
        printf("[%s] fb_hdr_v2.hdr_ver          = %d (0x%x)\n", MOD, fb_hdr_v2.hdr_ver, fb_hdr_v2.hdr_ver);
        printf("[%s] fb_hdr_v2.hash_count       = %d (0x%x)\n", MOD, fb_hdr_v2.hash_count, fb_hdr_v2.hash_count);
        printf("[%s] fb_hdr_v2.chunk_size       = %d (0x%x)\n", MOD, fb_hdr_v2.chunk_size, fb_hdr_v2.chunk_size);
        printf("[%s] fb_hdr_v2.part_name        = '%s' \n", MOD, fb_hdr_v2.part_name);
        printf("[%s] fb_hdr_v2.orig_img_size_64 = %lld (0x%llx)\n", MOD, fb_hdr_v2.orig_img_size_64,
               fb_hdr_v2.orig_img_size_64);
    } else {
        fb_hdr.magic_num = FB_IMG_MAGIC;
        fb_hdr.hdr_ver = 0x01;
        fb_hdr.chunk_size = g_fb_chunk_size;
        if (input_img_length <= (g_fb_chunk_size - FIX_FB_PADDING_HEADER_SIZE))
            fb_hdr.hash_count = 1;
        else
            fb_hdr.hash_count =
                    ((input_img_length - (g_fb_chunk_size - FIX_FB_PADDING_HEADER_SIZE) - 1) / g_fb_chunk_size) + 1 + 1;

        fb_chunk_count = fb_hdr.hash_count;
        memcpy(fb_hdr.part_name, input_img + last_slash_pot + 1, last_underscore_pot - last_slash_pot - 1);

        /* ------------------------------------- */
        /* dump information */
        /* ------------------------------------- */
        printf("[%s] fb_hdr.magic_num     = %d (0x%x)\n", MOD, fb_hdr.magic_num, fb_hdr.magic_num);
        printf("[%s] fb_hdr.hdr_ver       = %d (0x%x)\n", MOD, fb_hdr.hdr_ver, fb_hdr.hdr_ver);
        printf("[%s] fb_hdr.hash_count    = %d (0x%x)\n", MOD, fb_hdr.hash_count, fb_hdr.hash_count);
        printf("[%s] fb_hdr.chunk_size    = %d (0x%x)\n", MOD, fb_hdr.chunk_size, fb_hdr.chunk_size);
        printf("[%s] fb_hdr.part_name     = '%s' \n", MOD, fb_hdr.part_name);
        printf("[%s] fb_hdr.orig_img_size = %d (0x%x)\n", MOD, fb_hdr.orig_img_size, fb_hdr.orig_img_size);
    }


    /* ------------------------------------- */
    /* prepare fb chunk buffer */
    /* ------------------------------------- */
    fb_chunk_buffer = (unsigned char *) malloc(g_fb_chunk_size);
    if (fb_chunk_buffer == NULL) {
        ret = -3;
        printf("[%s] allocate for size '%d (0x%x)' of buffer failed\n", MOD, g_fb_chunk_size, g_fb_chunk_size);
        goto _fb_chunk_buf_alloc_fail;
    }
    memset(fb_chunk_buffer, 0x00, g_fb_chunk_size);

    /* ------------------------------------- */
    /* prepare mutiple hash buffer (include header) */
    /* ------------------------------------- */
    fb_multiple_hash_buffer_len = SEC_IMG_HDR_SZ + hash_size * fb_chunk_count;
    fb_multiple_hash_buffer = (unsigned char *) malloc(fb_multiple_hash_buffer_len);
    memset(fb_multiple_hash_buffer, 0x00, fb_multiple_hash_buffer_len);

    /* ------------------------------------- */
    /* prepare final signature file buffer */
    /* ------------------------------------- */
    sig_buf = (unsigned char *) malloc(sig_size);
    hash_buf = (unsigned char *) malloc(hash_size);
    fb_signature_file_buffer = (unsigned char *) malloc(FB_SIG_FILE_SIZE);
    memset(sig_buf, 0x00, sig_size);
    memset(hash_buf, 0x00, hash_size);
    memset(fb_signature_file_buffer, 0x00, FB_SIG_FILE_SIZE);

    /* ------------------------------------- */
    /* generate hash by fb chunk size*/
    /* ------------------------------------- */
    seek_pos = 0;
    fseeko(img_fd, seek_pos, SEEK_SET);
    left_size = input_img_length;
    current_chunk_count = 0;

    /* loop hash */
    while (left_size) {
        /* load data */
        if (current_chunk_count == 0)
            read_size = (left_size >= (g_fb_chunk_size - FIX_FB_PADDING_HEADER_SIZE)) ? (g_fb_chunk_size -
                                                                                         FIX_FB_PADDING_HEADER_SIZE)
                                                                                      : left_size;
        else
            read_size = (left_size >= g_fb_chunk_size) ? g_fb_chunk_size : left_size;

        fseeko(img_fd, seek_pos * sizeof(char), SEEK_SET);
        br = fread(fb_chunk_buffer, 1, read_size, img_fd);

        DBG("[%s] chunk[%d], read size %d (0x%x)\n", MOD, current_chunk_count, read_size, read_size);
#if DUMP_FB_FOR_DEBUG
        DBG("[%s] read pos 0x%llx, read size %d (0x%x)\n", MOD, seek_pos, read_size, read_size);
#endif

        if (br != read_size) {
            printf("[%s] read image content fail, read offset = '0x%llx'\n", MOD, seek_pos);
            printf("[%s] read image content fail, try read = '0x%x', return = '0x%x'\n", MOD, read_size, br);
            printf("[%s] read image content fail, errno = '%d', err str = '%s'\n", MOD, errno, strerror(errno));
            ret = -4;
            goto _read_file_error;
        }

        memset(hash_buf, 0x00, hash_size);
        /* caculate this hash */
        if (cust_hash(fb_chunk_buffer, read_size, hash_buf, hash_size) == -1) {
            printf("[%s] hash fail, offset is '0x%llx'(B)\n", MOD, seek_pos);
            ret = -5;
            goto _chunk_fb_hash_fail;
        }

#if DUMP_FB_FOR_DEBUG
        /* dump hash value for debug             */
        DBG("[%s] (loop)Data value(4 bytes) ==> (0x%x, 0x%x, 0x%x, 0x%x) \n",MOD,
                fb_chunk_buffer[0], fb_chunk_buffer[1], fb_chunk_buffer[2], fb_chunk_buffer[3]);
        DBG("[%s] (loop)Hash value (0x%llx):\n", MOD, seek_pos);
        for (i = 0; i < hash_size; i++)
            DBG("0x%x,", hash_buf[i]);
        DBG("\n");
#endif

        /* save this hash to compose buffer (first block) */
        memcpy(fb_multiple_hash_buffer + SEC_IMG_HDR_SZ + current_chunk_count * hash_size, hash_buf, hash_size);

        /* move next */
        seek_pos += read_size;
        left_size -= read_size;
        current_chunk_count += 1;
    }

    /* ------------------------------------- */
    /* generate final hash */
    /* ------------------------------------- */
    if (is_hdr_version4())
        memcpy(fb_multiple_hash_buffer, &fb_hdr_v2, SEC_IMG_HDR_SZ);
    else
        memcpy(fb_multiple_hash_buffer, &fb_hdr, SEC_IMG_HDR_SZ);
#if DUMP_FB_FOR_DEBUG
    /* dump multiple hash buffer for debug             */
    DBG("[%s] (final)multiple hash header value :\n", MOD);
    for (i = 0; i < SEC_IMG_HDR_SZ; i++) {
        DBG("0x%x,", fb_multiple_hash_buffer[i]);
        if ((i + 1) % 16 == 0) DBG("\n");

    }
    DBG("\n");
    DBG("[%s] (final)multiple hash data value :\n", MOD);
    for (i = 0;i < fb_multiple_hash_buffer_len - SEC_IMG_HDR_SZ; i++) {
        DBG("0x%x,", fb_multiple_hash_buffer[i + SEC_IMG_HDR_SZ]);
        if ((i + 1) % 20 == 0) DBG("\n");
    }
    DBG("\n");
#endif

    /* caculate this hash */
    memset(hash_buf, 0x00, hash_size);
    if (cust_hash(fb_multiple_hash_buffer, fb_multiple_hash_buffer_len, hash_buf, hash_size) == -1) {
        printf("[%s] final hash fail\n", MOD);
        ret = -6;
        goto _final_fb_hash_fail;
    }

#if DUMP_FB_FOR_DEBUG
    /* dump hash value for debug             */
    DBG("[%s] (final)Data value(4 bytes) ==> (0x%x, 0x%x, 0x%x, 0x%x) \n", MOD,
            fb_multiple_hash_buffer[0], fb_multiple_hash_buffer[1], fb_multiple_hash_buffer[2], fb_multiple_hash_buffer[3]);
    DBG("[%s] (final)Hash value : \n",MOD);
    for (i = 0; i < hash_size; i++)
        DBG("0x%x,", hash_buf[i]);
    DBG("\n");
#endif

    /* ------------------------------------- */
    /* generate final signature */
    /* ------------------------------------- */
    memset(sig_buf, 0x00, sig_size);
    if (cust_sign(hash_buf, hash_size, sig_buf, sig_size) == -1) {
        printf("[%s] final signature fail\n", MOD);
        ret = -7;
        goto _final_signature_fail;
    }
#if DUMP_FB_FOR_DEBUG
    /* dump signature value for debug             */
    DBG("[%s] (final)Data value(4 bytes) ==> (0x%x, 0x%x, 0x%x, 0x%x) \n", MOD,
            hash_buf[0], hash_buf[1], hash_buf[2], hash_buf[3]);
    DBG("[%s] (final)SIG value : \n",MOD);
    for (i = 0; i < sig_size; i++) {
        DBG("0x%x,", sig_buf[i]);
        if ((i+1)%16 == 0) DBG("\n");
    }
    DBG("\n");
#endif

    /* ------------------------------------- */
    /* prepare fb signature file buffer*/
    /* ------------------------------------- */
    memset(fb_signature_file_buffer, 0x00, FB_SIG_FILE_SIZE);

    if (is_hdr_version4())
        memcpy(fb_signature_file_buffer, &fb_hdr_v2, SEC_IMG_HDR_SZ);
    else
        memcpy(fb_signature_file_buffer, &fb_hdr, SEC_IMG_HDR_SZ);

    memcpy(fb_signature_file_buffer + SEC_IMG_HDR_SZ, sig_buf, sig_size);
    memcpy(fb_signature_file_buffer + SEC_IMG_HDR_SZ + sig_size, hash_buf, hash_size);

    /* ------------------------------------- */
    /* generate fb signature file */
    /* ------------------------------------- */
    FILE *fb_sig_fd = fopen(output_file, "wb");

    if (fb_sig_fd == 0) {
        printf("[%s] %s not found\n", MOD, output_file);
        ret = -8;
        goto _open_fb_sig_file_fail;
    }
    fwrite(fb_signature_file_buffer, 1, FB_SIG_FILE_SIZE, fb_sig_fd);

    fclose(fb_sig_fd);

    /* ------------------------------------- */
    /* generate fb padding header file */
    /* ------------------------------------- */
    FILE *fb_pad_hdr_fd = fopen(output_hdr, "wb");

    if (fb_pad_hdr_fd == 0) {
        printf("[%s] %s not found\n", MOD, output_hdr);
        ret = -9;
        goto _open_fb_pad_hdr_file_fail;
    }
    fb_pad_hdr_file_buffer = (unsigned char *) malloc(FIX_FB_PADDING_HEADER_SIZE);
    if (fb_pad_hdr_file_buffer == NULL) {
        ret = -10;
        printf("[%s] allocate for size '%d (0x%x)' of buffer failed\n", MOD, FIX_FB_PADDING_HEADER_SIZE,
               FIX_FB_PADDING_HEADER_SIZE);
        goto _fb_pad_hdr_buf_alloc_fail;
    }
    memset(fb_pad_hdr_file_buffer, 0x00, FIX_FB_PADDING_HEADER_SIZE);
    memcpy(fb_pad_hdr_file_buffer, fb_signature_file_buffer, FB_SIG_FILE_SIZE);
    memcpy(fb_pad_hdr_file_buffer + FB_SIG_FILE_SIZE, fb_multiple_hash_buffer, fb_multiple_hash_buffer_len);
    fwrite(fb_pad_hdr_file_buffer, 1, FIX_FB_PADDING_HEADER_SIZE, fb_pad_hdr_fd);

    free(fb_pad_hdr_file_buffer);

    _fb_pad_hdr_buf_alloc_fail:
    fclose(fb_pad_hdr_fd);
    _open_fb_pad_hdr_file_fail:
    _open_fb_sig_file_fail:
    _final_signature_fail:
    _final_fb_hash_fail:
    _chunk_fb_hash_fail:
    _read_file_error:
    free(fb_signature_file_buffer);
    free(hash_buf);
    free(sig_buf);
    free(fb_multiple_hash_buffer);
    free(fb_chunk_buffer);
    _fb_chunk_buf_alloc_fail:
    fclose(img_fd);
    input_img_err:
    orig_img_err:

    return ret;
}

