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
/// Non-sensitive member context implementation
/*! \file */

#include "epid/member/tpm/init.h"

#include <stddef.h>

#include "epid/member/tpm/src/types.h"
#include "epid/common/src/epid2params.h"
#include "epid/common/types.h"  // MemberPrecomp
#include "epid/common/math/finitefield.h"
#include "epid/common/math/ecgroup.h"
#include "epid/common/math/pairing.h"
#include "epid/common/src/memory.h"

/// Handle Intel(R) EPID Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

static EpidStatus TpmReadMemberPrecomputation(TpmCtx* ctx,
                                              MemberPrecomp const* precomp);

EpidStatus TpmInit(TpmCtx* ctx, G1ElemStr const* A_str, FpElemStr const* x_str,
                   G1ElemStr const* h1_str, G1ElemStr const* h2_str,
                   G2ElemStr const* w_str, MemberPrecomp const* precomp_str) {
  EpidStatus sts = kEpidErr;

  if (!ctx || !A_str || !x_str || !h1_str || !h2_str || !w_str ||
      !ctx->epid2_params) {
    return kEpidBadArgErr;
  }

  do {
    EcGroup* G1 = ctx->epid2_params->G1;
    EcGroup* G2 = ctx->epid2_params->G2;
    FiniteField* Fp = ctx->epid2_params->Fp;
    EcPoint* A = (EcPoint*)ctx->A;
    FfElement* x = (FfElement*)ctx->x;
    EcPoint* h1 = (EcPoint*)ctx->h1;
    EcPoint* h2 = (EcPoint*)ctx->h2;
    EcPoint* w = (EcPoint*)ctx->w;

    sts = ReadEcPoint(G1, A_str, sizeof(*A_str), A);
    BREAK_ON_EPID_ERROR(sts);

    sts = ReadFfElement(Fp, x_str, sizeof(*x_str), x);
    BREAK_ON_EPID_ERROR(sts);

    sts = ReadEcPoint(G1, h1_str, sizeof(*h1_str), h1);
    BREAK_ON_EPID_ERROR(sts);

    sts = ReadEcPoint(G1, h2_str, sizeof(*h2_str), h2);
    BREAK_ON_EPID_ERROR(sts);

    sts = ReadEcPoint(G2, w_str, sizeof(*w_str), w);
    BREAK_ON_EPID_ERROR(sts);

    sts = TpmReadMemberPrecomputation(ctx, precomp_str);
    BREAK_ON_EPID_ERROR(sts);

    sts = kEpidNoErr;
  } while (0);

  return sts;
}

static EpidStatus TpmReadMemberPrecomputation(TpmCtx* ctx,
                                              MemberPrecomp const* precomp) {
  EpidStatus sts = kEpidErr;

  if (!ctx || !precomp || !ctx->epid2_params) {
    return kEpidBadArgErr;
  }

  do {
    FiniteField* GT = ctx->epid2_params->GT;
    FfElement* e12 = (FfElement*)ctx->e12;
    FfElement* e22 = (FfElement*)ctx->e22;
    FfElement* e2w = (FfElement*)ctx->e2w;
    FfElement* ea2 = (FfElement*)ctx->ea2;

    sts = ReadFfElement(GT, &precomp->e12, sizeof(precomp->e12), e12);
    BREAK_ON_EPID_ERROR(sts);

    sts = ReadFfElement(GT, &precomp->e22, sizeof(precomp->e22), e22);
    BREAK_ON_EPID_ERROR(sts);

    sts = ReadFfElement(GT, &precomp->e2w, sizeof(precomp->e2w), e2w);
    BREAK_ON_EPID_ERROR(sts);

    sts = ReadFfElement(GT, &precomp->ea2, sizeof(precomp->ea2), ea2);
    BREAK_ON_EPID_ERROR(sts);

    sts = kEpidNoErr;
  } while (0);

  return sts;
}
