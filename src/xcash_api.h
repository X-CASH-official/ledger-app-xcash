/* Copyright 2017 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef XCASH_API_H
#define  XCASH_API_H


void xcash_install(unsigned char netId);
void xcash_init(void);
void xcash_init_private_key(void);
void xcash_wipe_private_key(void);

void xcash_init_ux(void);
int xcash_dispatch(void);

int xcash_apdu_put_key(void);
int xcash_apdu_get_key(void);
int xcash_apdu_manage_seedwords() ;
int xcash_apdu_verify_key(void);
int xcash_apdu_get_chacha8_prekey(void);
int xcash_apdu_sc_add(void);
int xcash_apdu_sc_sub(void);
int xcash_apdu_scal_mul_key(void);
int xcash_apdu_scal_mul_base(void);
int xcash_apdu_generate_keypair(void);
int xcash_apdu_secret_key_to_public_key(void);
int xcash_apdu_generate_key_derivation(void);
int xcash_apdu_derivation_to_scalar(void);
int xcash_apdu_derive_public_key(void);
int xcash_apdu_derive_secret_key(void);
int xcash_apdu_generate_key_image(void);
int xcash_apdu_derive_subaddress_public_key(void);
int xcash_apdu_get_subaddress(void);
int xcash_apdu_get_subaddress_spend_public_key(void);
int xcash_apdu_get_subaddress_secret_key(void);

int xcash_apdu_open_tx(void);
int xcash_apdu_open_subtx(void) ;
int xcash_apdu_set_signature_mode(void) ;
int xcash_apdu_stealth(void);
int xcash_apdu_blind(void);
int xcash_apdu_unblind(void);

int xcash_apdu_mlsag_prehash_init(void);
int xcash_apdu_mlsag_prehash_update(void);
int xcash_apdu_mlsag_prehash_finalize(void);
int xcash_apu_generate_txout_keys(void);

int xcash_apdu_mlsag_prepare(void);
int xcash_apdu_mlsag_hash(void);
int xcash_apdu_mlsag_sign(void);
int xcash_apdu_close_tx(void);

/* ----------------------------------------------------------------------- */
/* ---                               MISC                             ---- */
/* ----------------------------------------------------------------------- */
#define OFFSETOF(type, field)    ((unsigned int)&(((type*)NULL)->field))

int xcash_base58_public_key( char* str_b58, unsigned char *view, unsigned char *spend, unsigned char is_subbadress);

/** unsigned varint amount to uint64 */
uint64_t xcash_vamount2uint64(unsigned char *binary);
/** binary little endian unsigned  int amount to uint64 */
uint64_t xcash_bamount2uint64(unsigned char *binary);
/** unsigned varint amount to str */
int xcash_vamount2str(unsigned char *binary,  char *str, unsigned int str_len);
/** binary little endian unsigned  int amount to str */
int xcash_bamount2str(unsigned char *binary,  char *str, unsigned int str_len);
/** uint64  amount to str */
int xcash_amount2str(uint64_t xmr,  char *str, unsigned int str_len);

int xcash_abort_tx() ;
int xcash_unblind(unsigned char *v, unsigned char *k, unsigned char *AKout);
void ui_menu_validation_display(unsigned int value) ;
void ui_menu_fee_validation_display(unsigned int value) ;

/* ----------------------------------------------------------------------- */
/* ---                          KEYS & ADDRESS                        ---- */
/* ----------------------------------------------------------------------- */
void xcash_sc_add(unsigned char *r, unsigned char *s1, unsigned char *s2);
void xcash_hash_to_scalar(unsigned char *scalar, unsigned char *raw);
void xcash_hash_to_ec(unsigned char *ec, unsigned char *ec_pub);
void xcash_generate_keypair(unsigned char *ec_pub, unsigned char *ec_priv);
/*
 *  compute s = 8 * (k*P)
 *
 * s [out] 32 bytes derivation value
 * P [in]  point in 02 y or 04 x y format
 * k [in]  32 bytes scalar
 */
void xcash_generate_key_derivation(unsigned char *drv_data, unsigned char *P, unsigned char *scalar);
void xcash_derivation_to_scalar(unsigned char *scalar, unsigned char *drv_data, unsigned int out_idx);
/*
 *  compute x = Hps(drv_data,out_idx) + ec_pv
 *
 * x        [out] 32 bytes private key
 * drv_data [in]  32 bytes derivation data (point)
 * ec_pv    [in]  32 bytes private key
 */
void xcash_derive_secret_key(unsigned char *x, unsigned char *drv_data, unsigned int out_idx, unsigned char *ec_priv);
/*
 *  compute x = Hps(drv_data,out_idx)*G + ec_pub
 *
 * x        [out] 32 bytes public key
 * drv_data [in]  32 bytes derivation data (point)
 * ec_pub   [in]  32 bytes public key
 */
void xcash_derive_public_key(unsigned char *x, unsigned char* drv_data, unsigned int out_idx, unsigned char *ec_pub);
void xcash_secret_key_to_public_key(unsigned char *ec_pub, unsigned char *ec_priv);
void xcash_generate_key_image(unsigned char *img, unsigned char *P, unsigned char* x);

void xcash_derive_subaddress_public_key(unsigned char *x, unsigned char *pub, unsigned char* drv_data, unsigned int index);
void xcash_get_subaddress_spend_public_key(unsigned char *x,unsigned char *index);
void xcash_get_subaddress(unsigned char *C, unsigned char *D, unsigned char *index);
void xcash_get_subaddress_secret_key(unsigned char *sub_s, unsigned char *s, unsigned char *index);

void xcash_clear_words();
/* ----------------------------------------------------------------------- */
/* ---                              CRYPTO                            ---- */
/* ----------------------------------------------------------------------- */
extern const unsigned char C_ED25519_ORDER[];


void xcash_aes_derive(cx_aes_key_t *sk, unsigned char *R, unsigned char *a, unsigned char *b);
void xcash_aes_generate(cx_aes_key_t *sk);

/* Compute Monero-Hash of data*/
void xcash_hash_init_keccak(cx_hash_t * hasher);
void xcash_hash_init_sha256(cx_hash_t * hasher);
void xcash_hash_update(cx_hash_t * hasher, unsigned char* buf, unsigned int len) ;
int  xcash_hash_final(cx_hash_t * hasher, unsigned char* out);
int  xcash_hash(unsigned int algo, cx_hash_t * hasher, unsigned char* buf, unsigned int len, unsigned char* out);

#define xcash_keccak_F(buf,len,out) \
    xcash_hash(CX_KECCAK, (cx_hash_t *)&G_xcash_vstate.keccakF, (buf),(len), (out))

#define xcash_keccak_init_H() \
    xcash_hash_init_keccak((cx_hash_t *)&G_xcash_vstate.keccakH)
#define xcash_keccak_update_H(buf,len)  \
    xcash_hash_update((cx_hash_t *)&G_xcash_vstate.keccakH,(buf), (len))
#define xcash_keccak_final_H(out) \
    xcash_hash_final((cx_hash_t *)&G_xcash_vstate.keccakH, (out)?(out):G_xcash_vstate.H)
#define xcash_keccak_H(buf,len,out) \
    xcash_hash(CX_KECCAK, (cx_hash_t *)&G_xcash_vstate.keccakH, (buf),(len), (out)?(out):G_xcash_vstate.H)

#define xcash_sha256_commitment_init() \
    xcash_hash_init_sha256((cx_hash_t *)&G_xcash_vstate.sha256_commitment)
#define xcash_sha256_commitment_update(buf,len) \
    xcash_hash_update((cx_hash_t *)&G_xcash_vstate.sha256_commitment,(buf), (len))
#define xcash_sha256_commitment_final(out) \
    xcash_hash_final((cx_hash_t *)&G_xcash_vstate.sha256_commitment, (out)?(out):G_xcash_vstate.C)

#define xcash_sha256_amount_init() \
    xcash_hash_init_sha256((cx_hash_t *)&G_xcash_vstate.sha256_amount)
#define xcash_sha256_amount_update(buf,len) \
    xcash_hash_update((cx_hash_t *)&G_xcash_vstate.sha256_amount, (buf), (len))
#define xcash_sha256_amount_final(out) \
    xcash_hash_final((cx_hash_t *)&G_xcash_vstate.sha256_amount, (out)?(out):G_xcash_vstate.KV)

/**
 * LE-7-bits encoding. High bit set says one more byte to decode.
 */
unsigned int xcash_encode_varint(unsigned char varint[8], unsigned int out_idx);

/** */
void xcash_reverse32(unsigned char *rscal, unsigned char *scal);

/**
 * Hps: keccak(drv_data|varint(out_idx))
 */
void xcash_derivation_to_scalar(unsigned char *scalar, unsigned char *drv_data, unsigned int out_idx);

/** */
void xcash_hash_to_scalar(unsigned char *scalar, unsigned char *raw);


/*
 * W = k.P
 */
void xcash_ecmul_k(unsigned char *W, unsigned char *P, unsigned char *scalar32);
/*
 * W = 8k.P
 */
void xcash_ecmul_8k(unsigned char *W, unsigned char *P, unsigned char *scalar32);

/*
 * W = 8.P
 */
void xcash_ecmul_8(unsigned char *W, unsigned char *P);

/*
 * W = k.G
 */
void xcash_ecmul_G(unsigned char *W, unsigned char *scalar32);

/*
 * W = k.H
 */
void xcash_ecmul_H(unsigned char *W, unsigned char *scalar32);


/*
 * W = P+Q
 */
void xcash_ecadd(unsigned char *W, unsigned char *P, unsigned char *Q);
/*
 * W = P-Q
 */
void xcash_ecsub(unsigned char *W, unsigned char *P, unsigned char *Q);

/* r = (a+b) %order */
void xcash_addm(unsigned char *r, unsigned char *a, unsigned char *b);

/* r = (a-b) %order */
void xcash_subm(unsigned char *r, unsigned char *a, unsigned char *b);

/* r = (a*b) %order */
void xcash_multm(unsigned char *r, unsigned char *a, unsigned char *b);

/* r = (a*8) %order */
void xcash_multm_8(unsigned char *r, unsigned char *a);

/* */
void xcash_reduce(unsigned char *r, unsigned char *a);


void xcash_rng(unsigned char *r,  int len) ;
/* ----------------------------------------------------------------------- */
/* ---                                IO                              ---- */
/* ----------------------------------------------------------------------- */

void xcash_io_discard(int clear) ;
void xcash_io_clear(void);
void xcash_io_set_offset(unsigned int offset) ;
void xcash_io_mark(void) ;
void xcash_io_rewind(void) ;
void xcash_io_hole(unsigned int sz) ;
void xcash_io_inserted(unsigned int len);
void xcash_io_insert(unsigned char const * buffer, unsigned int len) ;
void xcash_io_insert_encrypt(unsigned char* buffer, int len);

void xcash_io_insert_u32(unsigned  int v32) ;
void xcash_io_insert_u24(unsigned  int v24) ;
void xcash_io_insert_u16(unsigned  int v16) ;
void xcash_io_insert_u8(unsigned int v8) ;
void xcash_io_insert_t(unsigned int T) ;
void xcash_io_insert_tl(unsigned int T, unsigned int L) ;
void xcash_io_insert_tlv(unsigned int T, unsigned int L, unsigned char const *V) ;

void xcash_io_fetch_buffer(unsigned char  * buffer, unsigned int len) ;
unsigned int xcash_io_fetch_u32(void) ;
unsigned int xcash_io_fetch_u24(void) ;
unsigned int xcash_io_fetch_u16(void) ;
unsigned int xcash_io_fetch_u8(void) ;
int xcash_io_fetch_t(unsigned int *T) ;
int xcash_io_fetch_l(unsigned int *L) ;
int xcash_io_fetch_tl(unsigned int *T, unsigned int *L) ;
int xcash_io_fetch_nv(unsigned char* buffer, int len) ;
int xcash_io_fetch(unsigned char* buffer, int len) ;
int xcash_io_fetch_decrypt(unsigned char* buffer, int len);
int xcash_io_fetch_decrypt_key(unsigned char* buffer);

int xcash_io_do(unsigned int io_flags) ;
/* ----------------------------------------------------------------------- */
/* ---                                DEBUG                           ---- */
/* ----------------------------------------------------------------------- */
#ifdef XCASH_DEBUG

#include "xcash_debug.h"

#else

#define xcash_nvm_write   nvm_write
#define xcash_io_exchange io_exchange

#endif

#endif
