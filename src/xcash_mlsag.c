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
#include "xcash_ux_nanos.h"
#include "xcash_vars.h"

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int xcash_apdu_mlsag_prepare() {
    int options;
    unsigned char Hi[32];
    unsigned char xin[32];
    unsigned char alpha[32];
    unsigned char mul[32];


    if (G_xcash_vstate.io_length>1) {        
        xcash_io_fetch(Hi,32);
        if(G_xcash_vstate.options &0x40) {
            xcash_io_fetch(xin,32);
        } else { 
           xcash_io_fetch_decrypt(xin,32); 
        }
        options = 1;
    }  else {
        options = 0;
    }

    xcash_io_discard(1);
    
    //ai
    xcash_rng(alpha, 32);
    xcash_reduce(alpha, alpha);
    xcash_io_insert_encrypt(alpha, 32);

    //ai.G
    xcash_ecmul_G(mul, alpha);
    xcash_io_insert(mul,32);
       
    if (options) {
        //ai.Hi
        xcash_ecmul_k(mul, Hi, alpha);
        xcash_io_insert(mul,32);
        //IIi = xin.Hi
        xcash_ecmul_k(mul, Hi, xin);
        xcash_io_insert(mul,32);
    }

    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int xcash_apdu_mlsag_hash() {
    unsigned char msg[32];
    unsigned char c[32];
    if (G_xcash_vstate.io_p2 == 1) {
        xcash_keccak_init_H();
        os_memmove(msg, G_xcash_vstate.H, 32);
    } else {
        xcash_io_fetch(msg, 32);
    }
    xcash_io_discard(1);

    xcash_keccak_update_H(msg, 32);
    if ((G_xcash_vstate.options&0x80) == 0 ) {
        xcash_keccak_final_H(c);
        xcash_reduce(c,c);
        xcash_io_insert(c,32);
        os_memmove(G_xcash_vstate.c, c, 32);
    }  
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int xcash_apdu_mlsag_sign() {
    unsigned char xin[32];
    unsigned char alpha[32];
    unsigned char ss[32];
    unsigned char ss2[32];
    
    if (G_xcash_vstate.sig_mode == TRANSACTION_CREATE_FAKE) {
        xcash_io_fetch(xin,32);
        xcash_io_fetch(alpha,32);
    } else if (G_xcash_vstate.sig_mode == TRANSACTION_CREATE_REAL) {
        xcash_io_fetch_decrypt(xin,32); 
        xcash_io_fetch_decrypt(alpha,32);
    } else {
        THROW(SW_WRONG_DATA);
    }
    xcash_io_discard(1);

    xcash_multm(ss, G_xcash_vstate.c, xin);
    xcash_subm(ss2, alpha, ss);

    xcash_io_insert(ss2,32);
    xcash_io_insert_u32(G_xcash_vstate.sig_mode);
    return SW_OK;
}
