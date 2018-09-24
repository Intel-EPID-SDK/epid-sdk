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
/// Precomputed signature management implementation.
/*! \file */

#define EXPORT_EPID_APIS
#include <epid/member/api.h>
#include "epid/member/tiny/src/context.h"
#include "epid/member/tiny/src/presig_compute.h"
#include "epid/member/tiny/src/stack.h"

EpidStatus EPID_MEMBER_API EpidAddPreSigs(MemberCtx* ctx,
                                          size_t number_presigs) {
  PreComputedSignatureData* new_presigs = NULL;
  size_t i = 0;
  if (!ctx) return kEpidBadArgErr;

  if (0 == number_presigs) return kEpidNoErr;

  new_presigs = StackPushN(&ctx->presigs, number_presigs, NULL);
  if (!new_presigs) return kEpidBadArgErr;

  for (i = 0; i < number_presigs; i++) {
    EpidStatus sts = EpidMemberComputePreSig(ctx, &new_presigs[i]);
    if (kEpidNoErr != sts) {
      // roll back pre-computed-signature pool
      StackPopN(&ctx->presigs, number_presigs);
      return sts;
    }
  }

  return kEpidNoErr;
}

size_t EPID_MEMBER_API EpidGetNumPreSigs(MemberCtx const* ctx) {
  return ctx ? StackGetSize(&ctx->presigs) : (size_t)0;
}

EpidStatus MemberTopPreSig(MemberCtx* ctx, PreComputedSignatureData** presig) {
  if (!ctx || !presig) {
    return kEpidBadArgErr;
  }

  if (!StackGetSize(&ctx->presigs)) {
    // if there is no presig, add one to heap so that it can be referenced from
    // StackTop()
    EpidStatus sts = EpidAddPreSigs(ctx, 1);
    if (kEpidNoErr != sts) {
      return sts;
    }
  }
  // Use existing pre-computed signature
  *presig = StackTop(&ctx->presigs);
  if (!*presig) {
    return kEpidErr;
  }
  return kEpidNoErr;
}

EpidStatus MemberPopPreSig(MemberCtx* ctx) {
  if (!ctx) {
    return kEpidBadArgErr;
  }

  if (!StackPopN(&ctx->presigs, 1)) {
    return kEpidErr;
  }
  return kEpidNoErr;
}
