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
/// TPM context implementation.
/*! \file */

#include "epid/member/split/tpm2/context.h"

#include <tss2/TPM_Types.h>
#include <tss2/tss.h>

#include "common/epid2params.h"
#include "epid/member/split/tpm2/flushcontext.h"
#include "epid/member/split/tpm2/getrandom.h"
#include "epid/member/split/tpm2/ibm_tss/printtss.h"
#include "epid/member/split/tpm2/ibm_tss/state.h"
#include "ippmath/finitefield.h"
#include "ippmath/memory.h"

/// Handle Intel(R) EPID Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

/// Flag that indicates that context was already created
bool is_context_already_created = false;

/// Internal Random function as a BitSupplier
static int __STDCALL tpm2_rnd_func(unsigned int* rand_data, int num_bits,
                                   void* user_data) {
  return Tpm2GetRandom((Tpm2Ctx*)user_data, num_bits, rand_data);
}

EpidStatus Tpm2CreateContext(MemberParams const* params,
                             Epid2Params_ const* epid2_params,
                             BitSupplier* rnd_func, void** rnd_param,
                             Tpm2Ctx** ctx) {
  EpidStatus sts = kEpidNoErr;
  TPM_RC rc = TPM_RC_FAILURE;
  Tpm2Ctx* tpm_ctx = NULL;
  if (!params || !epid2_params || !rnd_func || !rnd_param || !ctx) {
    return kEpidBadArgErr;
  }

  if (is_context_already_created) {
    return kEpidBadArgErr;
  }
  is_context_already_created = true;

  tpm_ctx = SAFE_ALLOC(sizeof(Tpm2Ctx));
  if (!tpm_ctx) {
    return kEpidMemAllocErr;
  }

  do {
    tpm_ctx->epid2_params = epid2_params;
    tpm_ctx->keys = NULL;

    rc = TSS_Create(&tpm_ctx->tss);
    if (rc != TPM_RC_SUCCESS) {
      sts = kEpidErr;
      break;
    }

    *ctx = tpm_ctx;
    *rnd_func = tpm2_rnd_func;
    *rnd_param = *ctx;
    sts = kEpidNoErr;
  } while (0);
  if (kEpidNoErr != sts) {
    Tpm2DeleteContext(&tpm_ctx);
    *ctx = NULL;
  }
  return sts;
}

void Tpm2DeleteContext(Tpm2Ctx** ctx) {
  is_context_already_created = false;
  if (ctx && *ctx) {
    size_t i = 0;
    for (i = 0; i < (*ctx)->max_keys; ++i) {
      Tpm2FlushContext(*ctx, &(*ctx)->keys[i]);
      (*ctx)->keys[i] = NULL;
    }
    SAFE_FREE((*ctx)->keys);
    TSS_Delete((*ctx)->tss);
    SAFE_FREE(*ctx);
  }
}
