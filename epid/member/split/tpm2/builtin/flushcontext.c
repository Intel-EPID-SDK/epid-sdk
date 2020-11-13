/*############################################################################
  # Copyright 2018-2019 Intel Corporation
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
/// TPM2_FlushContext command implementation.
/*! \file */

#include "epid/member/split/tpm2/flushcontext.h"
#include "epid/member/split/tpm2/builtin/state.h"
#include "epid/types.h"
#include "ippmath/finitefield.h"
#include "ippmath/memory.h"

EpidStatus Tpm2FlushContext(Tpm2Ctx* ctx, Tpm2Key** key) {
  size_t i = 0;
  if (!ctx || !key || !(*key)) {
    return kEpidBadArgErr;
  }

  for (i = 0; i < ctx->max_keys; i++) {
    if (*key == ctx->keys[i]) {
      DeleteFfElement(&(*key)->f);
      (*key)->hash_alg = kInvalidHashAlg;
      SAFE_FREE(*key);
      ctx->keys[i] = NULL;
      break;
    }
  }
  if (i == ctx->max_keys) {
    return kEpidBadArgErr;
  }

  return kEpidNoErr;
}
