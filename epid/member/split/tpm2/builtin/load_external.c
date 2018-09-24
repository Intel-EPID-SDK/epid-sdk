/*############################################################################
  # Copyright 2017-2018 Intel Corporation
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
/// TPM2_LoadExternal command implementation.
/*! \file */

#include "epid/member/split/tpm2/load_external.h"

#include "epid/common/math/finitefield.h"
#include "epid/common/src/epid2params.h"
#include "epid/common/src/memory.h"
#include "epid/member/split/tpm2/builtin/registerkey.h"
#include "epid/member/split/tpm2/builtin/state.h"
#include "epid/member/split/tpm2/flushcontext.h"

/// Handle Intel(R) EPID Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus Tpm2LoadExternal(Tpm2Ctx* ctx, HashAlg hash_alg,
                            FpElemStr const* f_str, Tpm2Key** key) {
  EpidStatus sts = kEpidErr;
  Tpm2Key* new_key = NULL;
  if (!ctx || !ctx->epid2_params || !f_str) {
    return kEpidBadArgErr;
  }

  if (kSha256 != hash_alg && kSha384 != hash_alg && kSha512 != hash_alg &&
      kSha512_256 != hash_alg)
    return kEpidHashAlgorithmNotSupported;

  new_key = SAFE_ALLOC(sizeof(Tpm2Key));
  if (!new_key) {
    return kEpidMemAllocErr;
  }
  sts = Tpm2RegisterKey(ctx, new_key);
  if (kEpidNoErr != sts) {
    SAFE_FREE(new_key);
    return sts;
  }

  do {
    FiniteField* Fp = ctx->epid2_params->Fp;

    sts = NewFfElement(Fp, &new_key->f);
    BREAK_ON_EPID_ERROR(sts);

    sts = ReadFfElement(Fp, f_str, sizeof(*f_str), new_key->f);
    BREAK_ON_EPID_ERROR(sts);

    new_key->hash_alg = hash_alg;
  } while (0);

  if (kEpidNoErr != sts) {
    Tpm2FlushContext(ctx, &new_key);
  } else {
    if (key) *key = new_key;
  }

  return sts;
}
