#pragma once

void set_hdr_version(SEC_IMG_HEADER_VER ver);

char is_hdr_version4();

char is_hdr_version3();

SEC_EXTENTION_CFG *get_ext_cfg();

unsigned int get_hash_size(SEC_CRYPTO_HASH_TYPE hash);

unsigned int get_sigature_size(SEC_CRYPTO_SIGNATURE_TYPE sig);

SEC_EXTENSTION_CRYPTO *allocate_ext_crypto();

SEC_FRAGMENT_CFG *allocate_ext_frag();

unsigned int get_ext_hash_only_struct_size(SEC_CRYPTO_HASH_TYPE hash);

SEC_EXTENSTION_HASH_ONLY *allocate_ext_hash_only(SEC_CRYPTO_HASH_TYPE hash);

unsigned int get_ext_hash_only_64_struct_size(SEC_CRYPTO_HASH_TYPE hash);

SEC_EXTENSTION_HASH_ONLY_64 *allocate_ext_hash_only_64(SEC_CRYPTO_HASH_TYPE hash);

unsigned int get_ext_hash_sig_struct_size(SEC_CRYPTO_HASH_TYPE hash, SEC_CRYPTO_SIGNATURE_TYPE sig);

SEC_EXTENSTION_HASH_SIG *allocate_ext_hash_sig(SEC_CRYPTO_HASH_TYPE hash, SEC_CRYPTO_SIGNATURE_TYPE sig);

unsigned int get_ext_sparse_struct_size(unsigned int sparse_data_len);

SEC_EXTENSTION_SPARSE *allocate_ext_sparse(unsigned int sparse_data_len);

SEC_EXTENSTION_END_MARK *allocate_ext_end();

int config_header_v1_v2_chk(SEC_IMG_HEADER *sec_hdr);

int config_header_v3_chk(unsigned long long img_len);
