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

#include "os.h"
#include "cx.h"
#include "xcash_types.h"
#include "xcash_api.h"
#include "xcash_vars.h"


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
 * HD wallet not yet supported : account is assumed to be zero
 */
#define OPTION_KEEP_r 1
int xcash_apdu_open_tx() {

    unsigned int account;

    //xcash_sha256_commitment_init();
    xcash_sha256_amount_init();

    account = xcash_io_fetch_u32();

    xcash_io_discard(1);

    xcash_rng(G_xcash_vstate.r,32);
    xcash_reduce(G_xcash_vstate.r, G_xcash_vstate.r);
    xcash_ecmul_G(G_xcash_vstate.R, G_xcash_vstate.r);

    xcash_io_insert(G_xcash_vstate.R,32);
    xcash_io_insert_encrypt(G_xcash_vstate.r,32);
#ifdef DEBUG_HWDEVICE    
    xcash_io_insert(G_xcash_vstate.r,32);
#endif
    return SW_OK;
}
#undef OPTION_KEEP_r

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int xcash_apdu_close_tx() {
   xcash_io_discard(0);
   return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
 * Sub dest address not yet supported: P1 = 2 not supported
 */
int xcash_abort_tx() {
    os_memset(G_xcash_vstate.r, 0, 32);
    os_memset(G_xcash_vstate.R, 0, 32);
    xcash_keccak_init_H();
    xcash_sha256_commitment_init();
    xcash_sha256_amount_init();
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
 * Sub dest address not yet supported: P1 = 2 not supported
 */
int xcash_apdu_set_signature_mode() {
    unsigned int sig_mode;

    G_xcash_vstate.sig_mode = TRANSACTION_CREATE_FAKE;

    sig_mode = xcash_io_fetch_u8();
    xcash_io_discard(0);
    switch(sig_mode) {
    case TRANSACTION_CREATE_REAL:
    case TRANSACTION_CREATE_FAKE:
        break;
    default:
        THROW(SW_WRONG_DATA);
    }
    G_xcash_vstate.sig_mode = sig_mode;

    xcash_io_insert_u32( G_xcash_vstate.sig_mode );
    return SW_OK;
}
