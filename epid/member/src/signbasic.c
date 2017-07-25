/*############################################################################
  # Copyright 2016-2017 Intel Corporation
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
 * \brief EpidSignBasic implementation.
 */

#include <string.h>  // memset

#include "epid/member/api.h"
#include "epid/member/src/context.h"
#include "epid/member/tpm/sign.h"
#include "epid/common/math/ecgroup.h"
#include "epid/common/math/finitefield.h"
#include "epid/common/src/epid2params.h"
#include "epid/member/src/hash_basename.h"
#include "epid/member/src/sign_commitment.h"
#include "epid/member/src/allowed_basenames.h"

/// Handle SDK Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus EpidSignBasic(MemberCtx const* ctx, void const* msg, size_t msg_len,
                         void const* basename, size_t basename_len,
                         BasicSignature* sig) {
  EpidStatus sts = kEpidErr;

  if (!ctx || !sig) {
    return kEpidBadArgErr;
  }
  if (!msg && (0 != msg_len)) {
    // if message is non-empty it must have both length and content
    return kEpidBadArgErr;
  }
  if (!basename && (0 != basename_len)) {
    // if basename is non-empty it must have both length and content
    return kEpidBadArgErr;
  }
  if (!ctx->epid2_params) {
    return kEpidBadArgErr;
  }

  do {
    FiniteField* Fp = ctx->epid2_params->Fp;
    EcGroup* G1 = ctx->epid2_params->G1;
    G1ElemStr B_str = {0};
    SignCommitOutput commit_out = {0};
    FpElemStr c_str = {0};

    if (basename) {
      if (!IsBasenameAllowed(ctx->allowed_basenames, basename, basename_len)) {
        sts = kEpidBadArgErr;
        BREAK_ON_EPID_ERROR(sts);
      }
      sts = HashBaseName(G1, ctx->hash_alg, basename, basename_len, &B_str);
      BREAK_ON_EPID_ERROR(sts);
      sts = TpmSignCommit(ctx->tpm_ctx, &B_str, &commit_out);
    } else {
      sts = TpmSignCommit(ctx->tpm_ctx, NULL, &commit_out);
    }
    BREAK_ON_EPID_ERROR(sts);

    sts = HashSignCommitment(Fp, ctx->hash_alg, &ctx->pub_key, &commit_out, msg,
                             msg_len, &c_str);
    BREAK_ON_EPID_ERROR(sts);

    sts = TpmSign(ctx->tpm_ctx, &c_str, &sig->sx, &sig->sf, &sig->sa, &sig->sb);
    BREAK_ON_EPID_ERROR(sts);

    sig->B = commit_out.B;
    sig->K = commit_out.K;
    sig->T = commit_out.T;
    sig->c = c_str;

    sts = kEpidNoErr;
  } while (0);

  return sts;
}
