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
int xcash_apdu_blind() {
    unsigned char v[32];
    unsigned char k[32];
    unsigned char AKout[32];

    xcash_io_fetch_decrypt(AKout,32);
    xcash_io_fetch(k,32);
    xcash_io_fetch(v,32);

    xcash_io_discard(1);

    //Update Hkv
    xcash_sha256_amount_update(AKout,32);
    xcash_sha256_amount_update(k,32);
    xcash_sha256_amount_update(v,32);

    //blind mask
    xcash_hash_to_scalar(AKout, AKout);
    xcash_addm(k,k,AKout);
    //blind value
    xcash_hash_to_scalar(AKout, AKout);
    xcash_addm(v,v,AKout);

    //ret all
    xcash_io_insert(v,32);
    xcash_io_insert(k,32);

    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */

int xcash_unblind(unsigned char *v, unsigned char *k, unsigned char *AKout) {
    xcash_hash_to_scalar(AKout, AKout);
    xcash_subm(k,k,AKout);
    xcash_hash_to_scalar(AKout, AKout);
    xcash_subm(v,v,AKout);
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int xcash_apdu_unblind() {
    unsigned char v[32];
    unsigned char k[32];
    unsigned char AKout[32];

    xcash_io_fetch_decrypt(AKout,32);
    xcash_io_fetch(k,32);
    xcash_io_fetch(v,32);

    xcash_io_discard(1);

    //unblind mask
    xcash_hash_to_scalar(AKout, AKout);
    xcash_subm(k,k,AKout);
    //unblind value
    xcash_hash_to_scalar(AKout, AKout);
    xcash_subm(v,v,AKout);

    //ret all
    xcash_io_insert(v,32);
    xcash_io_insert(k,32);

    return SW_OK;
}

