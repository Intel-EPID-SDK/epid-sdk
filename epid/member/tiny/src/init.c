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
/// Tiny member Init/Deinit implementation.
/*! \file */

#define EXPORT_EPID_APIS
#include <epid/member/api.h>

#include <stdint.h>
#include "epid/common/types.h"
#include "epid/member/tiny/math/fp.h"
#include "epid/member/tiny/math/mathtypes.h"
#include "epid/member/tiny/math/pairing.h"
#include "epid/member/tiny/math/serialize.h"
#include "epid/member/tiny/src/context.h"
#include "epid/member/tiny/src/presig_compute.h"
#include "epid/member/tiny/src/serialize.h"
#include "epid/member/tiny/src/stack.h"
#include "epid/member/tiny/stdlib/tiny_stdlib.h"
#include "epid/member/tiny_member.h"

static size_t SigrlGetSize(size_t num_sigrls) {
  return MIN_SIGRL_SIZE + num_sigrls * sizeof(SigRlEntry);
}
EpidStatus EPID_MEMBER_API EpidMemberGetSize(MemberParams const* params,
                                             size_t* context_size) {
  const size_t kMinContextSize =
      sizeof(MemberCtx) - sizeof(((MemberCtx*)0)->heap);
  if (!params || !context_size) {
    return kEpidBadArgErr;
  }
  *context_size = kMinContextSize + SigrlGetSize(params->max_sigrl_entries) +
                  BasenamesGetSize(params->max_allowed_basenames) +
                  sizeof(PreComputedSignatureData) * params->max_precomp_sig;
  return kEpidNoErr;
}

EpidStatus EPID_MEMBER_API EpidMemberInit(MemberParams const* params,
                                          MemberCtx* ctx) {
  EpidStatus sts = kEpidNoErr;
  size_t context_size = 0;
  if (!params || !ctx) {
    return kEpidBadArgErr;
  }

  sts = EpidMemberGetSize(params, &context_size);
  if (sts != kEpidNoErr) {
    return sts;
  }

  memset(ctx, 0, context_size);

  ctx->is_provisioned = 0;
  ctx->f_is_set = 0;

  // set the default hash algorithm to sha512
  ctx->hash_alg = kSha512;

  // set allowed basenames pointer to the heap
  ctx->allowed_basenames =
      (AllowedBasenames*)&ctx->heap[SigrlGetSize(params->max_sigrl_entries)];
  InitBasenames(ctx->allowed_basenames, params->max_allowed_basenames);
  // set precomputed signatures pointer to the heap
  // There must be space at least for one presig
  if (!params->max_precomp_sig) {
    return kEpidBadArgErr;
  }
  InitPreSigStack(&ctx->presigs, params->max_precomp_sig,
                  &ctx->heap[SigrlGetSize(params->max_sigrl_entries) +
                             BasenamesGetSize(params->max_allowed_basenames)]);
  if (params->f) {
    FpDeserialize(&ctx->f, params->f);
    if (!FpInField(&ctx->f)) {
      memset(&ctx->f, 0, sizeof(ctx->f));
      return kEpidBadArgErr;
    }
    ctx->f_is_set = 1;
  }
  ctx->rnd_func = params->rnd_func;
  ctx->rnd_param = params->rnd_param;
  ctx->max_sigrl_entries = params->max_sigrl_entries;
  ctx->max_allowed_basenames = params->max_allowed_basenames;
  ctx->max_precomp_sig = params->max_precomp_sig;
  PairingInit(&ctx->pairing_state);
  return kEpidNoErr;
}

void EPID_MEMBER_API EpidMemberDeinit(MemberCtx* ctx) {
  (void)ctx;
  return;
}

EpidStatus EPID_MEMBER_API EpidMemberCreate(MemberParams const* params,
                                            MemberCtx** ctx) {
  (void)params;
  (void)ctx;
  return kEpidNotImpl;
}

void EPID_MEMBER_API EpidMemberDelete(MemberCtx** ctx) { (void)ctx; }
