/*############################################################################
  # Copyright 2016-2019 Intel Corporation
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

/*!
 * \file
 * \brief Member context implementation.
 */
#define EXPORT_EPID_APIS
#include <epid/member/api.h>

#include <string.h>
#include "common/endian_convert.h"
#include "common/epid2params.h"
#include "common/sigrlvalid.h"
#include "common/stack.h"
#include "epid/member/split/allowed_basenames.h"
#include "epid/member/split/context.h"
#include "epid/member/split/precomp.h"
#include "epid/member/split/tpm2/context.h"
#include "epid/member/split/tpm2/createprimary.h"
#include "epid/member/split/tpm2/flushcontext.h"
#include "epid/member/split/tpm2/keyinfo.h"
#include "epid/member/split/tpm2/load_external.h"
#include "epid/member/split/tpm2/sign.h"
#include "epid/types.h"
#include "ippmath/ecgroup.h"
#include "ippmath/finitefield.h"
#include "ippmath/memory.h"

/// Handle SDK Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus EPID_MEMBER_API EpidMemberGetSize(MemberParams const* params,
                                             size_t* context_size) {
  if (!params || !context_size) {
    return kEpidBadArgErr;
  }
  *context_size = sizeof(MemberCtx);
  return kEpidNoErr;
}

EpidStatus EPID_MEMBER_API EpidMemberInit(MemberParams const* params,
                                          MemberCtx* ctx) {
  EpidStatus sts = kEpidErr;
  FfElement* ff_elem = NULL;

  if (!params || !ctx) {
    return kEpidBadArgErr;
  }
  EpidZeroMemory(ctx, sizeof(*ctx));
  do {
    ctx->sig_rl = NULL;
    ctx->precomp_ready = false;
    ctx->is_provisioned = false;
    ctx->f_handle = NULL;

    sts = CreateBasenames(&ctx->allowed_basenames);
    BREAK_ON_EPID_ERROR(sts);
    // Internal representation of Epid2Params
    sts = CreateEpid2Params(&ctx->epid2_params);
    BREAK_ON_EPID_ERROR(sts);

    // create TPM2 context
    sts = Tpm2CreateContext(params, ctx->epid2_params, &ctx->rnd_func,
                            &ctx->rnd_param, &ctx->tpm2_ctx);
    BREAK_ON_EPID_ERROR(sts);

    if (params->f) {
      FiniteField* Fp = ctx->epid2_params->Fp;
      ctx->external_f = SAFE_ALLOC(sizeof(*ctx->external_f));
      if (!ctx->external_f) {
        return kEpidMemAllocErr;
      }
      // Validate f
      sts = NewFfElement(Fp, &ff_elem);
      BREAK_ON_EPID_ERROR(sts);
      sts = ReadFfElement(Fp, params->f, sizeof(*params->f), ff_elem);
      BREAK_ON_EPID_ERROR(sts);

      *(ctx->external_f) = *(params->f);
    }

    if (!CreateStack(sizeof(PreComputedSignature), &ctx->presigs)) {
      sts = kEpidMemAllocErr;
      BREAK_ON_EPID_ERROR(sts);
    }

    sts = NewEcPoint(ctx->epid2_params->G1, (EcPoint**)&ctx->A);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(ctx->epid2_params->Fp, (FfElement**)&ctx->x);
    BREAK_ON_EPID_ERROR(sts);

    sts = NewEcPoint(ctx->epid2_params->G1, (EcPoint**)&ctx->h1);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(ctx->epid2_params->G1, (EcPoint**)&ctx->h2);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(ctx->epid2_params->G2, (EcPoint**)&ctx->w);
    BREAK_ON_EPID_ERROR(sts);

    sts = NewFfElement(ctx->epid2_params->GT, (FfElement**)&ctx->e12);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(ctx->epid2_params->GT, (FfElement**)&ctx->e22);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(ctx->epid2_params->GT, (FfElement**)&ctx->e2w);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(ctx->epid2_params->GT, (FfElement**)&ctx->ea2);
    BREAK_ON_EPID_ERROR(sts);

    sts = kEpidNoErr;
  } while (0);
  DeleteFfElement(&ff_elem);
  if (kEpidNoErr != sts) {
    EpidMemberDeinit(ctx);
  }

  return (sts);
}

void EPID_MEMBER_API EpidMemberDeinit(MemberCtx* ctx) {
  size_t i = 0;
  size_t presig_size = 0;
  PreComputedSignature* buf = NULL;
  if (!ctx) {
    return;
  }
  presig_size = StackGetSize(ctx->presigs);
  buf = StackGetBuf(ctx->presigs);
  for (i = 0; i < presig_size; ++i) {
    if (buf->is_rf_ctr_set == true) {
      (void)Tpm2ReleaseCounter(ctx->tpm2_ctx, (buf++)->rf_ctr, ctx->f_handle);
    }
  }
  Tpm2FlushContext(ctx->tpm2_ctx, &ctx->f_handle);
  ctx->f_handle = NULL;
  DeleteStack(&ctx->presigs);
  ctx->rnd_param = NULL;
  DeleteEcPoint((EcPoint**)&(ctx->h1));
  DeleteEcPoint((EcPoint**)&(ctx->h2));
  DeleteEcPoint((EcPoint**)&(ctx->A));
  DeleteFfElement((FfElement**)&ctx->x);
  DeleteEcPoint((EcPoint**)&(ctx->w));
  DeleteFfElement((FfElement**)&ctx->e12);
  DeleteFfElement((FfElement**)&ctx->e22);
  DeleteFfElement((FfElement**)&ctx->e2w);
  DeleteFfElement((FfElement**)&ctx->ea2);
  Tpm2DeleteContext(&ctx->tpm2_ctx);
  SAFE_FREE(ctx->external_f);
  DeleteEpid2Params(&ctx->epid2_params);
  DeleteBasenames(&ctx->allowed_basenames);
}

EpidStatus EPID_MEMBER_API EpidMemberCreate(MemberParams const* params,
                                            MemberCtx** ctx) {
  size_t context_size = 0;
  EpidStatus sts = kEpidErr;
  MemberCtx* member_ctx = NULL;
  if (!params || !ctx) {
    return kEpidBadArgErr;
  }
  do {
    sts = EpidMemberGetSize(params, &context_size);
    BREAK_ON_EPID_ERROR(sts);
    member_ctx = SAFE_ALLOC(context_size);
    if (!member_ctx) {
      sts = kEpidMemAllocErr;
      break;
    }
    sts = EpidMemberInit(params, member_ctx);
    BREAK_ON_EPID_ERROR(sts);
  } while (0);
  if (kEpidNoErr != sts) {
    SAFE_FREE(member_ctx);
    member_ctx = NULL;
  }
  *ctx = member_ctx;
  return sts;
}

EpidStatus CreatePrivateF(MemberCtx* ctx, HashAlg hash_alg,
                          Tpm2Key** f_handle) {
  EpidStatus sts = kEpidErr;

  if (!ctx || !f_handle) {
    return kEpidBadArgErr;
  }

  do {
    if (ctx->external_f) {
      sts =
          Tpm2LoadExternal(ctx->tpm2_ctx, hash_alg, ctx->external_f, f_handle);
      BREAK_ON_EPID_ERROR(sts);
    } else {
      sts = Tpm2CreatePrimary(ctx->tpm2_ctx, hash_alg, f_handle);
      BREAK_ON_EPID_ERROR(sts);
    }
    sts = kEpidNoErr;
  } while (0);
  return sts;
}

void EPID_MEMBER_API EpidMemberDelete(MemberCtx** ctx) {
  if (!ctx) {
    return;
  }
  EpidMemberDeinit(*ctx);
  SAFE_FREE(*ctx);
  *ctx = NULL;
}

EpidStatus EPID_MEMBER_API EpidMemberSetHashAlg(MemberCtx* ctx,
                                                HashAlg hash_alg) {
  if (!ctx) {
    return kEpidBadArgErr;
  }
  if (Tpm2KeyHashAlg(ctx->f_handle) != hash_alg) {
    return kEpidOperationNotSupportedErr;
  }
  return kEpidNoErr;
}

EpidStatus EPID_MEMBER_API EpidMemberSetSigRl(MemberCtx* ctx,
                                              SigRl const* sig_rl,
                                              size_t sig_rl_size) {
  if (!ctx || !sig_rl) {
    return kEpidBadArgErr;
  }
  if (!ctx->is_provisioned) {
    return kEpidOutOfSequenceError;
  }
  if (!IsSigRlValid(&ctx->pub_key.gid, sig_rl, sig_rl_size)) {
    return kEpidBadArgErr;
  }
  // Do not set an older version of sig rl
  if (ctx->sig_rl) {
    unsigned int current_ver = 0;
    unsigned int incoming_ver = 0;
    current_ver = ntohl(ctx->sig_rl->version);
    incoming_ver = ntohl(sig_rl->version);
    if (incoming_ver < current_ver) {
      return kEpidVersionMismatchErr;
    }
  }
  ctx->sig_rl = sig_rl;

  return kEpidNoErr;
}

EpidStatus EPID_MEMBER_API EpidRegisterBasename(MemberCtx* ctx,
                                                void const* basename,
                                                size_t basename_len) {
  EpidStatus sts = kEpidErr;
  if (basename_len == 0) {
    return kEpidBadArgErr;
  }
  if (!ctx || !basename) {
    return kEpidBadArgErr;
  }

  if (IsBasenameAllowed(ctx->allowed_basenames, basename, basename_len)) {
    return kEpidDuplicateErr;
  }

  sts = AllowBasename(ctx->allowed_basenames, basename, basename_len);

  return sts;
}

EpidStatus EPID_MEMBER_API EpidClearRegisteredBasenames(MemberCtx* ctx) {
  EpidStatus sts = kEpidErr;
  if (!ctx) {
    return kEpidBadArgErr;
  }
  DeleteBasenames(&ctx->allowed_basenames);
  sts = CreateBasenames(&ctx->allowed_basenames);
  return sts;
}
