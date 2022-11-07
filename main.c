#include <stdio.h>
#include <string.h>
#include "lib_sign.h"

int main(int argc, char *argv[]) {
    FILE *gen_fd = NULL;
    char gen_header = 0;

    /* ------------------------------------- */
    /* dump information                      */
    /* ------------------------------------- */
    printf("\n=========================================\n");
    printf("[Android SignTool]\n\n");
    printf("Built at %s\n", "Thu Feb 9 21:19:50 CST 2012");
    printf("=========================================\n\n");

    /* ------------------------------------- */
    /* parse arguments                       */
    /* ------------------------------------- */
    if (argc == 6) {
        printf("[%s] sign image ... \n", "SignTool");
    } else if (argc == 5) {
        printf("[%s] generate hdr file ...\n", "SignTool");
        gen_header = 1;
    } else {
        printf("Usage:    Sign Image .. \n");
        printf("          ./SignTool [KEY] [CONFIG] [INPUT_IMAGE] [OUTPUT_SIGNATURE] [OUTPUT_HEADER]\n\n");

        printf("Example:\n");
        printf("          ./SignTool IMG_KEY.ini IMG_CFG.ini u-boot.bin u-boot-signature u-boot-header\n\n");

        printf("Usage:    Output Key Information for Linking .. \n");
        printf("          ./SignTool [KEY] [CONFIG] [OUTPUT_C_HEADER] [OUTPUT_PREFIX]\n\n");

        printf("Example:\n");
        printf("          ./SignTool IMG_KEY.ini IMG_CFG.ini GEN_IMG_KEY.h IMG\n");
        return -1;

    }

    /* ------------------------------------- */
    /* open auto-gen header                  */
    /* ------------------------------------- */
    if (1 == gen_header) {
        gen_fd = fopen(argv[3], "wb");
        fwrite("// [", 1, strlen("// ["), gen_fd);
        fwrite(argv[3], 1, strlen(argv[3]), gen_fd);
        fwrite("]\n// BUILD TIME : ", 1, strlen("]\n// BUILD TIME : "), gen_fd);
        fwrite("Thu Feb 9 21:19:50 CST 2012", 1, strlen("Thu Feb 9 21:19:50 CST 2012"), gen_fd);
        fwrite("\n", 1, strlen("\n"), gen_fd);
    }

    /* ------------------------------------- */
    /* import key                            */
    /* ------------------------------------- */
    if (0 != imp_key(argv[1], argv[4], gen_header, gen_fd)) {
        return -1;
    }

    if (0 == gen_header) {
        /* ------------------------------------- */
        /* check if this image is signed already */
        /* ------------------------------------- */
        if (0 != chk_img(argv[3])) {
            return -1;
        }

        /* ------------------------------------- */
        /* create and write header               */
        /* ------------------------------------- */
        if (0 != gen_hdr(argv[2], argv[5], argv[3], argv[4])) {
            return -1;
        }

        /* ------------------------------------- */
        /* hash and sign image                   */
        /* ------------------------------------- */
        if (0 != pro_img(argv[4], argv[3], argv[5])) {
            return -1;
        }
    }

    printf("\n");

    return 0;
}
