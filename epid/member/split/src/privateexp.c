/*############################################################################
  # Copyright 2017-2019 Intel Corporation
  #
  # Licensed under the Apache License, Version 2.0 (the "License");
  # you may not use this file except in compliance with the License.
  # You may obtain a copy of the License at
  #
  #     http://www.apache.org/licenses/LICENSE-2.0
  #
  # Unless required by applicable law or agreed to in writing, software
  # distributed under the License is distributed on an "AS IS" BASIS,
  # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  # See the License for the specific language governing permissions and
  # limitations under the License.
  ############################################################################*/
/// Member private exponentiation implementation
/*! \file */

#include "epid/member/split/privateexp.h"

#include <stdio.h>
#include "common/epid2params.h"
#include "common/hashsize.h"
#include "epid/member/split/context.h"
#include "epid/member/split/tpm2/commit.h"
#include "epid/member/split/tpm2/keyinfo.h"
#include "epid/member/split/tpm2/sign.h"
#include "epid/types.h"
#include "ippmath/ecgroup.h"
#include "ippmath/memory.h"

/// Handle Intel(R) EPID Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

/// Sha Digest Element
typedef union sha_digest {
  uint8_t sha512_digest[EPID_SHA512_DIGEST_BITSIZE / CHAR_BIT];
  uint8_t sha384_digest[EPID_SHA384_DIGEST_BITSIZE / CHAR_BIT];
  uint8_t sha256_digest[EPID_SHA256_DIGEST_BITSIZE / CHAR_BIT];
  uint8_t digest[1];  ///< Pointer to digest
} sha_digest;
#pragma pack(1)
/// Structure to store values to create commitment in EpidPrivateExp
typedef struct PrivateExpCommitValues {
  FpElemStr nonce_k;  ///< Nonce produced by the TPM during signing
  sha_digest digest;
} PrivateExpCommitValues;
#pragma pack()

EpidStatus EpidPrivateExp(MemberCtx* ctx, EcPoint const* a,
                          Tpm2Key const* f_handle, EcPoint* r) {
  EpidStatus sts = kEpidErr;

  BigNumStr tmp_ff_str = {0};
  uint16_t counter = 0;
  bool is_counter_set = false;

  EcPoint* k_pt = NULL;
  EcPoint* l_pt = NULL;
  EcPoint* e_pt = NULL;
  EcPoint* t1 = NULL;
  EcPoint* h = NULL;

  FfElement* k = NULL;
  FfElement* s = NULL;

  size_t digest_len = 0;
  PrivateExpCommitValues commit_values = {0};
  size_t commit_len = 0;

  if (!ctx || !ctx->epid2_params || !a || !f_handle || !r) {
    return kEpidBadArgErr;
  }

  digest_len = EpidGetHashSize(Tpm2KeyHashAlg(f_handle));
  if (sizeof(commit_values.digest) < digest_len) {
    return kEpidBadArgErr;
  }

  do {
    FiniteField* Fp = ctx->epid2_params->Fp;
    EcGroup* G1 = ctx->epid2_params->G1;

    // (K_PT, L_PT, E_PT, counter) = TPM2_Commit(P1=B')
    sts = NewEcPoint(G1, &k_pt);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &l_pt);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &e_pt);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &t1);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &h);
    BREAK_ON_EPID_ERROR(sts);

    sts = Tpm2Commit(ctx->tpm2_ctx, f_handle, a, NULL, 0, NULL, k_pt, l_pt,
                     e_pt, &counter);
    BREAK_ON_EPID_ERROR(sts);
    is_counter_set = true;

    // (k, s) = TPM2_Sign(c=0, counter)
    sts = NewFfElement(Fp, &k);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &s);
    BREAK_ON_EPID_ERROR(sts);

    sts = Tpm2Sign(ctx->tpm2_ctx, f_handle, &commit_values.digest, digest_len,
                   counter, k, s);
    BREAK_ON_EPID_ERROR(sts);
    is_counter_set = false;
    // k1 = Fq.hash(k || c)
    sts = WriteFfElement(Fp, k, &commit_values.nonce_k,
                         sizeof(commit_values.nonce_k));
    BREAK_ON_EPID_ERROR(sts);
    commit_len = sizeof(commit_values.nonce_k) + digest_len;
    // note : k is reused as k1
    sts = FfHash(Fp, &commit_values, commit_len, Tpm2KeyHashAlg(f_handle), k);
    BREAK_ON_EPID_ERROR(sts);

    // k1 = Fq.inv(k1)
    sts = FfInv(Fp, k, k);
    BREAK_ON_EPID_ERROR(sts);

    // t1 = G1.sscmExp(B', s)
    sts = WriteFfElement(Fp, s, &tmp_ff_str, sizeof(tmp_ff_str));
    BREAK_ON_EPID_ERROR(sts);
    sts = EcSscmExp(G1, a, &tmp_ff_str, t1);
    BREAK_ON_EPID_ERROR(sts);

    // E_PT = G1.inv(E_PT)
    sts = EcInverse(G1, e_pt, e_pt);
    BREAK_ON_EPID_ERROR(sts);

    // h = G1.mul(t1, E_PT)
    sts = EcMul(G1, t1, e_pt, h);
    BREAK_ON_EPID_ERROR(sts);

    // h = G1.sscmExp(h, k1)
    sts = WriteFfElement(Fp, k, &tmp_ff_str, sizeof(tmp_ff_str));
    BREAK_ON_EPID_ERROR(sts);
    sts = EcSscmExp(G1, h, &tmp_ff_str, r);
    BREAK_ON_EPID_ERROR(sts);
  } while (0);

  if (is_counter_set == true) {
    (void)Tpm2ReleaseCounter(ctx->tpm2_ctx, counter, f_handle);
  }
  DeleteFfElement(&s);
  DeleteFfElement(&k);

  DeleteEcPoint(&e_pt);
  DeleteEcPoint(&l_pt);
  DeleteEcPoint(&k_pt);
  DeleteEcPoint(&t1);
  DeleteEcPoint(&h);

  EpidZeroMemory(&tmp_ff_str, sizeof(tmp_ff_str));
  return sts;
}
