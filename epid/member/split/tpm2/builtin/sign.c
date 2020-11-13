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
/// Tpm2Sign implementation.
/*! \file  */

#include "epid/member/split/tpm2/sign.h"

#include <string.h>

#include "common/epid2params.h"
#include "common/hashsize.h"
#include "epid/member/split/tpm2/builtin/state.h"
#include "epid/types.h"
#include "ippmath/finitefield.h"
#include "ippmath/memory.h"

/// Handle Intel(R) EPID Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

/// Handle unused variables
#define UNUSED(a) (void)a;

/// Sha Digest Element
typedef union sha_digest {
  uint8_t sha512_digest[EPID_SHA512_DIGEST_BITSIZE / CHAR_BIT];
  uint8_t sha384_digest[EPID_SHA384_DIGEST_BITSIZE / CHAR_BIT];
  uint8_t sha256_digest[EPID_SHA256_DIGEST_BITSIZE / CHAR_BIT];
  uint8_t digest[1];  ///< Pointer to digest
} sha_digest;

#pragma pack(1)
typedef struct Tpm2SignCommitValues {
  BigNumStr noncek;  //!< random number (256-bit)
  sha_digest digest;
} Tpm2SignCommitValues;
#pragma pack()

static EpidStatus GetCommitNonce(Tpm2Ctx* ctx, uint16_t counter,
                                 FfElement** r) {
  if (!ctx || counter == 0 || !r) {
    return kEpidBadArgErr;
  }
  if (counter >= MAX_COMMIT_COUNT) {
    return kEpidBadArgErr;
  }
  *r = ctx->commit_data[counter - 1];
  return kEpidNoErr;
}

static void ClearCommitNonce(Tpm2Ctx* ctx, uint16_t counter) {
  if (ctx && counter > 0 && counter < MAX_COMMIT_COUNT) {
    DeleteFfElement(&ctx->commit_data[counter - 1]);
  }
}

EpidStatus Tpm2Sign(Tpm2Ctx* ctx, Tpm2Key const* key, void const* digest,
                    size_t digest_len, uint16_t counter, FfElement* k,
                    FfElement* s) {
  EpidStatus sts = kEpidErr;
  FfElement* t = NULL;
  FfElement* commit_nonce = NULL;
  Tpm2SignCommitValues commit_values;
  FfElement* noncek = NULL;

  if (!ctx || !digest || !s || !ctx->epid2_params || !key) {
    return kEpidBadArgErr;
  }
  if (0 == digest_len || EpidGetHashSize(key->hash_alg) != digest_len) {
    return kEpidBadArgErr;
  }
  if (sizeof(commit_values.digest) < digest_len) {
    return kEpidBadArgErr;
  }
  if (!key->f) {
    return kEpidBadArgErr;
  }

  do {
    FpElemStr tmp_str;
    FiniteField* Fp = ctx->epid2_params->Fp;
    const BigNumStr zero = {0};
    size_t commit_len = 0;

    sts = NewFfElement(Fp, &noncek);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfGetRandom(Fp, &zero, ctx->rnd_func, ctx->rnd_param, noncek);
    BREAK_ON_EPID_ERROR(sts);
    commit_len = sizeof(commit_values.noncek) + digest_len;
    sts = WriteFfElement(Fp, noncek, &commit_values.noncek,
                         sizeof(commit_values.noncek));
    BREAK_ON_EPID_ERROR(sts);
    if (0 != memcpy_S(&commit_values.digest, sizeof(commit_values.digest),
                      digest, digest_len)) {
      sts = kEpidBadArgErr;
      BREAK_ON_EPID_ERROR(sts);
    }

    sts = GetCommitNonce(ctx, counter, &commit_nonce);
    BREAK_ON_EPID_ERROR(sts);

    sts = NewFfElement(Fp, &t);
    BREAK_ON_EPID_ERROR(sts);

    // a. set T = Hash( noncek||| digest) (mod p)
    sts = FfHash(Fp, &commit_values, commit_len, key->hash_alg, t);
    BREAK_ON_EPID_ERROR(sts);
    // b. compute integer s = (r + T*f)(mod p)
    sts = FfMul(Fp, key->f, t, s);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfAdd(Fp, commit_nonce, s, s);
    BREAK_ON_EPID_ERROR(sts);

    // d. if s = 0, output failure (negligible probability)
    sts = WriteFfElement(Fp, s, &tmp_str, sizeof(tmp_str));
    BREAK_ON_EPID_ERROR(sts);
    if (0 == memcmp(&zero, &tmp_str, sizeof(tmp_str))) {
      sts = kEpidBadArgErr;
      break;
    }

    if (k) {
      // k = noncek
      sts = ReadFfElement(Fp, &commit_values.noncek,
                          sizeof(commit_values.noncek), k);
      BREAK_ON_EPID_ERROR(sts);
    }
    ClearCommitNonce(ctx, counter);
    sts = kEpidNoErr;
  } while (0);
  DeleteFfElement(&t);
  DeleteFfElement(&noncek);

  return sts;
}

EpidStatus Tpm2ReleaseCounter(Tpm2Ctx* ctx, uint16_t counter,
                              Tpm2Key const* key) {
  UNUSED(key);
  if (!ctx) {
    return kEpidBadArgErr;
  }

  ClearCommitNonce(ctx, counter);
  return kEpidNoErr;
}
