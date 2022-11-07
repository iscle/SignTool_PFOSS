#pragma once

int imp_key(char *kf, char *kp, char gen_hdr, FILE *gen_fd);

int chk_img(char *img_name);

int gen_hdr(char *cfg_name, char *hdr_name, char *img_name, char *hs_name);

int pro_img(char *hs_name, char *img_name, char *hdr_name);