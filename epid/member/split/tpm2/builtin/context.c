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
/// TPM context implementation.
/*! \file */

#include <stddef.h>

#include "epid/common/math/finitefield.h"
#include "epid/common/src/epid2params.h"
#include "epid/common/src/memory.h"
#include "epid/member/software_member.h"
#include "epid/member/split/tpm2/builtin/state.h"
#include "epid/member/split/tpm2/context.h"
#include "epid/member/split/tpm2/flushcontext.h"

/// Handle Intel(R) EPID Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus Tpm2CreateContext(MemberParams const* params,
                             Epid2Params_ const* epid2_params,
                             BitSupplier* rnd_func, void** rnd_param,
                             Tpm2Ctx** ctx) {
  Tpm2Ctx* tpm_ctx = NULL;
  EpidStatus sts = kEpidNoErr;

  if (!params || !epid2_params || !rnd_func || !rnd_param || !ctx) {
    return kEpidBadArgErr;
  }

  tpm_ctx = SAFE_ALLOC(sizeof(Tpm2Ctx));
  if (!tpm_ctx) {
    return kEpidMemAllocErr;
  }

  do {
    int i;
    FiniteField* Fp = epid2_params->Fp;
    sts = NewFfElement(Fp, &tpm_ctx->seed);
    BREAK_ON_EPID_ERROR(sts);
    if (params->f) {
      // note: params->f == seed for built-in tpm implementation
      sts = ReadFfElement(Fp, params->f, sizeof(*params->f), tpm_ctx->seed);
      BREAK_ON_EPID_ERROR(sts);
    } else {
      // select random seed
      const BigNumStr kOne = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
      sts = FfGetRandom(Fp, &kOne, params->rnd_func, params->rnd_param,
                        tpm_ctx->seed);
      BREAK_ON_EPID_ERROR(sts);
    }
    tpm_ctx->epid2_params = epid2_params;
    tpm_ctx->rnd_func = params->rnd_func;
    tpm_ctx->rnd_param = params->rnd_param;
    tpm_ctx->keys = NULL;
    tpm_ctx->max_keys = 0;
    *rnd_func = params->rnd_func;
    *rnd_param = params->rnd_param;

    for (i = 0; i < MAX_NV_NUMBER; ++i) {
      tpm_ctx->nv[i].nv_index = 0;
      tpm_ctx->nv[i].data = NULL;
      tpm_ctx->nv[i].data_size = 0;
    }

    memset(tpm_ctx->commit_data, 0, sizeof(tpm_ctx->commit_data));

    *ctx = tpm_ctx;
    sts = kEpidNoErr;
  } while (0);

  if (kEpidNoErr != sts) {
    Tpm2DeleteContext(&tpm_ctx);
    *ctx = NULL;
  }
  return sts;
}

void Tpm2DeleteContext(Tpm2Ctx** ctx) {
  if (ctx && *ctx) {
    size_t i;
    (*ctx)->rnd_param = NULL;

    for (i = 0; i < (*ctx)->max_keys; ++i) {
      Tpm2FlushContext(*ctx, &(*ctx)->keys[i]);
      (*ctx)->keys[i] = NULL;
    }
    SAFE_FREE((*ctx)->keys);
    (*ctx)->max_keys = 0;

    DeleteFfElement(&(*ctx)->seed);
    for (i = 0; i < MAX_COMMIT_COUNT; ++i) {
      DeleteFfElement(&(*ctx)->commit_data[i]);
    }
    for (i = 0; i < MAX_NV_NUMBER; ++i) {
      (*ctx)->nv->nv_index = 0;
      SAFE_FREE((*ctx)->nv->data);
      (*ctx)->nv->data_size = 0;
    }
    SAFE_FREE(*ctx);
  }
}
