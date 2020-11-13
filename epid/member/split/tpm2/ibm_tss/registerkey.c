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
/// RegisterKey implementation.
/*! \file */

#include "epid/member/split/tpm2/ibm_tss/registerkey.h"

#include "epid/member/split/tpm2/ibm_tss/state.h"
#include "ippmath/memory.h"

EpidStatus Tpm2RegisterKey(Tpm2Ctx* ctx, Tpm2Key* key) {
  size_t index = 0;
  Tpm2Key** new_keys = NULL;

  if (!ctx || !key) {
    return kEpidBadArgErr;
  }

  // search for empty slot
  for (index = 0; index < ctx->max_keys; index++) {
    if (!ctx->keys[index]) break;
  }

  // allocate slot
  if (index >= ctx->max_keys) {
    new_keys = SAFE_REALLOC(ctx->keys, (index + 1) * sizeof(*ctx->keys));
    if (!new_keys) {
      return kEpidMemAllocErr;
    }
    ctx->keys = new_keys;
    ctx->max_keys = index + 1;
  }

  ctx->keys[index] = key;

  return kEpidNoErr;
}
