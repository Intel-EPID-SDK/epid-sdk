/*############################################################################
  # Copyright 2017 Intel Corporation
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
/// Sensitive member context implementation
/*! \file */

#include "epid/member/tpm/context.h"

#include <stddef.h>

#include "epid/member/tpm/src/types.h"
#include "epid/common/src/memory.h"
#include "epid/common/src/epid2params.h"
#include "epid/common/src/stack.h"
#include "epid/common/types.h"  // MemberPrecomp
#include "epid/common/math/finitefield.h"
#include "epid/common/math/ecgroup.h"

/// Handle Intel(R) EPID Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus TpmCreate(BitSupplier rnd_func, void* rnd_param,
                     Epid2Params_ const* epid2_params, TpmCtx** ctx) {
  EpidStatus sts = kEpidErr;
  TpmCtx* tpm_ctx = NULL;

  if (!epid2_params || !ctx) {
    return kEpidBadArgErr;
  }

  tpm_ctx = SAFE_ALLOC(sizeof(TpmCtx));
  if (!tpm_ctx) {
    return kEpidMemAllocErr;
  }

  do {
    FiniteField* Fp = epid2_params->Fp;

    if (!CreateStack(sizeof(PreComputedSignature), &tpm_ctx->secret.presigs)) {
      sts = kEpidMemAllocErr;
      BREAK_ON_EPID_ERROR(sts);
    }

    tpm_ctx->epid2_params = epid2_params;
    tpm_ctx->rnd_func = rnd_func;
    tpm_ctx->secret.rnd_param = rnd_param;
    tpm_ctx->secret.sign_pending = false;
    tpm_ctx->secret.nrprove_pending = false;
    tpm_ctx->secret.join_pending = false;

    sts = NewFfElement(Fp, &tpm_ctx->secret.a);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &tpm_ctx->secret.b);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &tpm_ctx->secret.rx);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &tpm_ctx->secret.rf);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &tpm_ctx->secret.ra);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &tpm_ctx->secret.rb);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &tpm_ctx->secret.mu);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &tpm_ctx->secret.nu);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &tpm_ctx->secret.rmu);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &tpm_ctx->secret.rnu);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &tpm_ctx->secret.r);
    BREAK_ON_EPID_ERROR(sts);

    sts = NewFfElement(Fp, (FfElement**)&tpm_ctx->secret.f);
    BREAK_ON_EPID_ERROR(sts);

    sts = NewEcPoint(tpm_ctx->epid2_params->G1, (EcPoint**)&tpm_ctx->A);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, (FfElement**)&tpm_ctx->x);
    BREAK_ON_EPID_ERROR(sts);

    sts = NewEcPoint(tpm_ctx->epid2_params->G1, (EcPoint**)&tpm_ctx->h1);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(tpm_ctx->epid2_params->G1, (EcPoint**)&tpm_ctx->h2);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(tpm_ctx->epid2_params->G2, (EcPoint**)&tpm_ctx->w);
    BREAK_ON_EPID_ERROR(sts);

    sts = NewFfElement(tpm_ctx->epid2_params->GT, (FfElement**)&tpm_ctx->e12);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(tpm_ctx->epid2_params->GT, (FfElement**)&tpm_ctx->e22);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(tpm_ctx->epid2_params->GT, (FfElement**)&tpm_ctx->e2w);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(tpm_ctx->epid2_params->GT, (FfElement**)&tpm_ctx->ea2);
    BREAK_ON_EPID_ERROR(sts);

    *ctx = tpm_ctx;

    sts = kEpidNoErr;
  } while (0);

  if (kEpidNoErr != sts) {
    TpmDelete(&tpm_ctx);
  }

  return sts;
}

void TpmDelete(TpmCtx** ctx) {
  if (ctx && *ctx) {
    (*ctx)->secret.rnd_param = NULL;
    DeleteStack(&(*ctx)->secret.presigs);
    DeleteFfElement((FfElement**)&(*ctx)->secret.f);
    DeleteFfElement((FfElement**)&(*ctx)->secret.a);
    DeleteFfElement((FfElement**)&(*ctx)->secret.b);
    DeleteFfElement((FfElement**)&(*ctx)->secret.rx);
    DeleteFfElement((FfElement**)&(*ctx)->secret.rf);
    DeleteFfElement((FfElement**)&(*ctx)->secret.ra);
    DeleteFfElement((FfElement**)&(*ctx)->secret.rb);
    DeleteFfElement((FfElement**)&(*ctx)->secret.mu);
    DeleteFfElement((FfElement**)&(*ctx)->secret.nu);
    DeleteFfElement((FfElement**)&(*ctx)->secret.rmu);
    DeleteFfElement((FfElement**)&(*ctx)->secret.rnu);
    DeleteFfElement((FfElement**)&(*ctx)->secret.r);
    DeleteEcPoint((EcPoint**)&((*ctx)->h1));
    DeleteEcPoint((EcPoint**)&((*ctx)->h2));
    DeleteEcPoint((EcPoint**)&((*ctx)->A));
    DeleteFfElement((FfElement**)&(*ctx)->x);
    DeleteEcPoint((EcPoint**)&((*ctx)->w));
    DeleteFfElement((FfElement**)&(*ctx)->e12);
    DeleteFfElement((FfElement**)&(*ctx)->e22);
    DeleteFfElement((FfElement**)&(*ctx)->e2w);
    DeleteFfElement((FfElement**)&(*ctx)->ea2);
    SAFE_FREE(*ctx);
  }
}

EpidStatus TpmProvision(TpmCtx* ctx, FpElemStr const* f_str) {
  EpidStatus sts = kEpidErr;
  if (!ctx || !ctx->epid2_params) {
    return kEpidBadArgErr;
  }

  do {
    FiniteField* Fp = ctx->epid2_params->Fp;
    FfElement* f = (FfElement*)ctx->secret.f;

    sts = ReadFfElement(Fp, f_str, sizeof(*f_str), f);
    BREAK_ON_EPID_ERROR(sts);
    sts = kEpidNoErr;
  } while (0);

  return sts;
}

EpidStatus TpmProvisionCompressed(TpmCtx* ctx, OctStr256 const* seed) {
  if (!ctx || !seed) {
    return kEpidBadArgErr;
  } else {
    OctStr256* ctx_seed = (OctStr256*)&ctx->secret.seed;
    *ctx_seed = *seed;
  }
  return kEpidNoErr;
}
