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

/*
* Client: rctSigs.cpp.c -> get_pre_mlsag_hash
*/

#include "os.h"
#include "cx.h"
#include "xcash_types.h"
#include "xcash_api.h"
#include "xcash_ux_nanos.h"
#include "xcash_vars.h"

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int xcash_apdu_mlsag_prehash_init() {
    if (G_xcash_vstate.io_p2 == 1) {
        xcash_sha256_amount_final(NULL);
        xcash_sha256_amount_init();
        xcash_sha256_commitment_init();
        xcash_keccak_init_H();
    }
    xcash_keccak_update_H(G_xcash_vstate.io_buffer+G_xcash_vstate.io_offset,
                          G_xcash_vstate.io_length-G_xcash_vstate.io_offset);
    if ((G_xcash_vstate.sig_mode == TRANSACTION_CREATE_REAL) &&(G_xcash_vstate.io_p2==1)) {
        // skip type
        xcash_io_fetch_u8();
        // fee str
        xcash_vamount2str(G_xcash_vstate.io_buffer+G_xcash_vstate.io_offset, G_xcash_vstate.ux_amount, 15);
         //ask user
        xcash_io_discard(1);
        ui_menu_fee_validation_display(0);
        return 0;
    } else {
        xcash_io_discard(1);
        return SW_OK;
    }
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int xcash_apdu_mlsag_prehash_update() {
    unsigned char is_subaddress;
    unsigned char Aout[32];
    unsigned char Bout[32];
    #define aH    Aout
    #define kG    Bout
    #define AKout Aout
    unsigned char C[32];
    unsigned char v[32];
    unsigned char k[32];
    int changed;
    changed = 0;

    is_subaddress = xcash_io_fetch_u8();
    xcash_io_fetch(Aout,32);
    xcash_io_fetch(Bout,32);
    if (G_xcash_vstate.sig_mode == TRANSACTION_CREATE_REAL) {
        if (os_memcmp(Aout, G_xcash_vstate.A, 32) || os_memcmp(Bout, G_xcash_vstate.B, 32) ) {
            //encode dest adress
            xcash_base58_public_key(&G_xcash_vstate.ux_address[0], Aout, Bout, is_subaddress);
        } else {
            changed = 1;
        }
    }
    xcash_io_fetch_decrypt(AKout,32);
    xcash_io_fetch(C,32);
    xcash_io_fetch(k,32);
    xcash_io_fetch(v,32);

    xcash_io_discard(1);

    //update MLSAG prehash
    xcash_keccak_update_H(k,32);
    xcash_keccak_update_H(v,32);

    //unblind amount, mask and update amount hash control
    xcash_sha256_amount_update(AKout,32);
    xcash_unblind(v,k, AKout);
    xcash_sha256_amount_update(k, 32);
    xcash_sha256_amount_update(v, 32);

    //check C = aH+kG
    xcash_ecmul_G(kG, k);
    if (!cx_math_is_zero(v, 32)) {
        xcash_ecmul_H(aH, v);
        xcash_ecadd(k, kG, aH);
    } else {
        os_memmove(k, kG, 32);
    }
    if (os_memcmp(C, k, 32)) {
        THROW(SW_SECURITY_COMMITMENT_CONTROL);
    }

    //update commitment hash control
    xcash_sha256_commitment_update(C,32);

    if ((G_xcash_vstate.options & IN_OPTION_MORE_COMMAND)==0) {
        //finalize and check amount hash_control
        xcash_sha256_amount_final(k);
        if (os_memcmp(k, G_xcash_vstate.KV, 32)) {
            THROW(SW_SECURITY_AMOUNT_CHAIN_CONTROL);
        }
        //finalize commitment hash control
        xcash_sha256_commitment_final(NULL);
        xcash_sha256_commitment_init();
    }

    if (G_xcash_vstate.sig_mode == TRANSACTION_CREATE_REAL) {
        //ask user
        uint64_t amount;        
        amount = xcash_bamount2uint64(v);
        if (!changed && amount) {
            xcash_amount2str(amount, G_xcash_vstate.ux_amount, 15);
            ui_menu_validation_display(0);
            return 0;
        }
    }
    return SW_OK;

    #undef aH
    #undef kG
    #undef AKout
}


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int xcash_apdu_mlsag_prehash_finalize() {
    unsigned char message[32];
    unsigned char proof[32];
    unsigned char H[32];

    if (G_xcash_vstate.options & IN_OPTION_MORE_COMMAND) {
        //accumulate
        xcash_io_fetch(H,32);
        xcash_io_discard(1);
        xcash_keccak_update_H(H,32);
        xcash_sha256_commitment_update(H,32);
#ifdef DEBUG_HWDEVICE
        xcash_io_insert(H, 32);
#endif

    } else {
        //Finalize and check commitment hash control
        xcash_sha256_commitment_final(H);
        if (os_memcmp(H,G_xcash_vstate.C,32)) {
            THROW(SW_SECURITY_COMMITMENT_CHAIN_CONTROL);
        }
        //compute last H
        xcash_keccak_final_H(H);
        //compute last prehash
        xcash_io_fetch(message,32);
        xcash_io_fetch(proof,32);
        xcash_io_discard(1);
        xcash_keccak_init_H();
        xcash_keccak_update_H(message,32);
        xcash_keccak_update_H(H,32);
        xcash_keccak_update_H(proof,32);
        xcash_keccak_final_H(NULL);
#ifdef DEBUG_HWDEVICE
        xcash_io_insert(G_xcash_vstate.H, 32);
        xcash_io_insert(H, 32);
#endif
    }

    return SW_OK;
}

