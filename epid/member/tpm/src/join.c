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
/// TPM join implementation
/*! \file */

#include "epid/member/tpm/join.h"

#include "epid/member/tpm/src/types.h"
#include "epid/common/src/epid2params.h"
#include "epid/common/math/bignum.h"
#include "epid/common/math/ecgroup.h"
#include "epid/common/math/finitefield.h"

/// Handle Intel(R) EPID Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus TpmJoinCommit(TpmCtx* ctx, G1ElemStr* F_str, G1ElemStr* R_str) {
  EpidStatus sts = kEpidErr;

  EcPoint* t = NULL;  // temporary used for F and R

  if (!ctx || !F_str || !R_str || !ctx->epid2_params) {
    return kEpidBadArgErr;
  }

  do {
    FiniteField* Fp = ctx->epid2_params->Fp;
    EcGroup* G1 = ctx->epid2_params->G1;
    FfElement const* f = ctx->secret.f;
    FfElement* r = ctx->secret.r;
    EcPoint const* h1 = ctx->h1;
    const BigNumStr one = {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}};
    BigNumStr exp_str = {0};

    sts = NewEcPoint(G1, &t);
    BREAK_ON_EPID_ERROR(sts);

    // 2. The member computes F = G1.sscmExp(h1, f).
    sts = WriteFfElement(Fp, f, &exp_str, sizeof(exp_str));
    BREAK_ON_EPID_ERROR(sts);
    sts = EcExp(G1, h1, (BigNumStr const*)&exp_str, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteEcPoint(G1, t, F_str, sizeof(F_str));
    BREAK_ON_EPID_ERROR(sts);

    // 1. The member chooses a random integer r from [1, p-1].
    sts = FfGetRandom(Fp, &one, ctx->rnd_func, ctx->secret.rnd_param, r);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, r, &exp_str, sizeof(exp_str));
    BREAK_ON_EPID_ERROR(sts);

    // 3. The member computes R = G1.sscmExp(h1, r).
    sts = EcExp(G1, h1, (BigNumStr const*)&exp_str, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteEcPoint(G1, t, R_str, sizeof(R_str));
    BREAK_ON_EPID_ERROR(sts);

    ctx->secret.join_pending = true;

    sts = kEpidNoErr;
  } while (0);

  DeleteEcPoint(&t);

  return sts;
}

/// Performs the last part of the join operation
EpidStatus TpmJoin(TpmCtx* ctx, FpElemStr const* c_str, FpElemStr* s_str) {
  EpidStatus sts = kEpidErr;

  FfElement* t = NULL;  // temporary multiplication sts

  if (!ctx || !c_str || !s_str || !ctx->epid2_params) {
    return kEpidBadArgErr;
  }

  if (!ctx->secret.join_pending) {
    return kEpidOutOfSequenceError;
  }

  do {
    FiniteField* Fp = ctx->epid2_params->Fp;
    FfElement const* f = ctx->secret.f;
    FfElement* r = ctx->secret.r;

    // Step 5. The member computes s = (r + c * f) mod p.
    sts = NewFfElement(Fp, &t);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadFfElement(Fp, c_str, sizeof(*c_str), t);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfMul(Fp, t, f, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfAdd(Fp, r, t, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, t, s_str, sizeof(*s_str));
    BREAK_ON_EPID_ERROR(sts);

    ctx->secret.join_pending = false;

    sts = kEpidNoErr;
  } while (0);

  DeleteFfElement(&t);

  return sts;
}
