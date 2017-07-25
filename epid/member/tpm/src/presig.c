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
/// Sensitive pre-computed signature implementation
/*! \file */

#include "epid/member/tpm/presig.h"

#include <string.h>

#include "epid/member/tpm/src/types.h"
#include "epid/common/src/stack.h"
#include "epid/common/math/ecgroup.h"
#include "epid/common/math/finitefield.h"
#include "epid/common/src/epid2params.h"
#include "epid/common/src/memory.h"

/// Handle Intel(R) EPID Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

/// Count of elements in array
#define COUNT_OF(A) (sizeof(A) / sizeof((A)[0]))

static EpidStatus TpmComputePreSig(TpmCtx const* ctx,
                                   PreComputedSignature* precompsig);

EpidStatus TpmAddPreSigs(TpmCtx* ctx, size_t number_presigs) {
  PreComputedSignature* new_presigs = NULL;
  size_t i = 0;
  if (!ctx || !ctx->secret.presigs) return kEpidBadArgErr;

  if (0 == number_presigs) return kEpidNoErr;

  new_presigs = (PreComputedSignature*)StackPushN(ctx->secret.presigs,
                                                  number_presigs, NULL);
  if (!new_presigs) return kEpidMemAllocErr;

  for (i = 0; i < number_presigs; i++) {
    EpidStatus sts = TpmComputePreSig(ctx, &new_presigs[i]);
    if (kEpidNoErr != sts) {
      // roll back pre-computed-signature pool
      StackPopN(ctx->secret.presigs, number_presigs, 0);
      return sts;
    }
  }

  return kEpidNoErr;
}

size_t TpmGetNumPreSigs(TpmCtx const* ctx) {
  return (ctx && ctx->secret.presigs) ? StackGetSize(ctx->secret.presigs)
                                      : (size_t)0;
}

EpidStatus TpmGetPreSig(TpmCtx* ctx, PreComputedSignature* presig) {
  EpidStatus sts = kEpidErr;
  if (!ctx || !presig) {
    return kEpidBadArgErr;
  }

  if (StackGetSize(ctx->secret.presigs)) {
    // Use existing pre-computed signature
    if (!StackPopN(ctx->secret.presigs, 1, presig)) {
      return kEpidErr;
    }
  }
  // generate a new pre-computed signature
  sts = TpmComputePreSig(ctx, presig);
  return sts;
}

/// Performs Pre-computation that can be used to speed up signing
static EpidStatus TpmComputePreSig(TpmCtx const* ctx,
                                   PreComputedSignature* precompsig) {
  EpidStatus sts = kEpidErr;

  EcPoint* B = NULL;
  EcPoint* t = NULL;  // temporary, used for K, T, R1

  FfElement* R2 = NULL;

  FfElement* a = NULL;
  FfElement* rx = NULL;  // reused for rf
  FfElement* rb = NULL;  // reused for ra

  FfElement* t1 = NULL;
  FfElement* t2 = NULL;
  BigNumStr f_str = {0};
  BigNumStr t1_str = {0};
  BigNumStr t2_str = {0};

  if (!ctx || !precompsig || !ctx->epid2_params) {
    return kEpidBadArgErr;
  }

  do {
    // handy shorthands:
    EcGroup* G1 = ctx->epid2_params->G1;
    FiniteField* GT = ctx->epid2_params->GT;
    FiniteField* Fp = ctx->epid2_params->Fp;
    EcPoint const* h2 = ctx->h2;
    EcPoint const* A = ctx->A;
    FfElement const* x = ctx->x;
    FfElement const* f = ctx->secret.f;

    const BigNumStr one = {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}};
    // 1. The member expects the pre-computation is done (e12, e22, e2w,
    //    ea2). Refer to Section 3.5 for the computation of these
    //    values.

    // The following variables B, K, T, R1 (elements of G1), R2
    // (elements of GT), a, b, rx, rf, ra, rb, t1, t2 (256-bit
    // integers) are used.
    sts = NewEcPoint(G1, &B);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &t);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(GT, &R2);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &a);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &rx);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &rb);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &t1);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &t2);
    BREAK_ON_EPID_ERROR(sts);

    // 3. The member computes B = G1.getRandom().
    sts = EcGetRandom(G1, ctx->rnd_func, ctx->secret.rnd_param, B);
    BREAK_ON_EPID_ERROR(sts);

    sts = WriteEcPoint(G1, B, &precompsig->B, sizeof(precompsig->B));
    BREAK_ON_EPID_ERROR(sts);

    // 4. The member computes K = G1.sscmExp(B, f).
    sts = WriteFfElement(Fp, f, &f_str, sizeof(f_str));
    BREAK_ON_EPID_ERROR(sts);
    sts = EcExp(G1, B, &f_str, t);
    BREAK_ON_EPID_ERROR(sts);

    sts = WriteEcPoint(G1, t, &precompsig->K, sizeof(precompsig->K));
    BREAK_ON_EPID_ERROR(sts);

    // 5. The member chooses randomly an integer a from [1, p-1].
    sts = FfGetRandom(Fp, &one, ctx->rnd_func, ctx->secret.rnd_param, a);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, a, &precompsig->a, sizeof(precompsig->a));
    BREAK_ON_EPID_ERROR(sts);
    // 6. The member computes T = G1.sscmExp(h2, a).
    sts = EcExp(G1, h2, (BigNumStr*)&precompsig->a, t);
    BREAK_ON_EPID_ERROR(sts);
    // 7. The member computes T = G1.mul(T, A).
    sts = EcMul(G1, t, A, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteEcPoint(G1, t, &precompsig->T, sizeof(precompsig->T));
    BREAK_ON_EPID_ERROR(sts);

    // 9. The member chooses rx, rf, ra, rb randomly from [1, p-1].

    // note : rx & rb are reused as rf & ra respectively
    sts = FfGetRandom(Fp, &one, ctx->rnd_func, ctx->secret.rnd_param, rx);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfGetRandom(Fp, &one, ctx->rnd_func, ctx->secret.rnd_param, rb);
    BREAK_ON_EPID_ERROR(sts);

    sts = WriteFfElement(Fp, rx, &precompsig->rx, sizeof(precompsig->rx));
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, rb, &precompsig->rb, sizeof(precompsig->rb));
    BREAK_ON_EPID_ERROR(sts);

    // 10. The member computes t1 = (- rx) mod p.
    sts = FfNeg(Fp, rx, t1);
    BREAK_ON_EPID_ERROR(sts);

    // 11. The member computes t2 = (rb - a * rx) mod p.
    sts = FfMul(Fp, a, rx, t2);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfNeg(Fp, t2, t2);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfAdd(Fp, rb, t2, t2);
    BREAK_ON_EPID_ERROR(sts);

    // 8. The member computes b = (a * x) mod p.
    sts = FfMul(Fp, a, x, a);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, a, &precompsig->b, sizeof(precompsig->b));
    BREAK_ON_EPID_ERROR(sts);

    // reusing rx as rf and rb as ra
    sts = FfGetRandom(Fp, &one, ctx->rnd_func, ctx->secret.rnd_param, rx);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfGetRandom(Fp, &one, ctx->rnd_func, ctx->secret.rnd_param, rb);
    BREAK_ON_EPID_ERROR(sts);

    sts = WriteFfElement(Fp, rx, &precompsig->rf, sizeof(precompsig->rf));
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, rb, &precompsig->ra, sizeof(precompsig->ra));
    BREAK_ON_EPID_ERROR(sts);

    // 12. The member computes R1 = G1.sscmExp(B, rf).
    sts = EcExp(G1, B, (BigNumStr*)&precompsig->rf, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteEcPoint(G1, t, &precompsig->R1, sizeof(precompsig->R1));
    BREAK_ON_EPID_ERROR(sts);

    // 13. The member computes R2 = GT.sscmMultiExp(ea2, t1, e12, rf,
    //     e22, t2, e2w, ra).
    sts = WriteFfElement(Fp, t1, &t1_str, sizeof(t1_str));
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, t2, &t2_str, sizeof(t2_str));
    BREAK_ON_EPID_ERROR(sts);
    {
      FfElement const* points[4];
      BigNumStr const* exponents[4];
      points[0] = ctx->ea2;
      points[1] = ctx->e12;
      points[2] = ctx->e22;
      points[3] = ctx->e2w;
      exponents[0] = &t1_str;
      exponents[1] = (BigNumStr*)&precompsig->rf;
      exponents[2] = &t2_str;
      exponents[3] = (BigNumStr*)&precompsig->ra;
      sts = FfMultiExp(GT, points, exponents, COUNT_OF(points), R2);
      BREAK_ON_EPID_ERROR(sts);
    }

    sts = WriteFfElement(GT, R2, &precompsig->R2, sizeof(precompsig->R2));
    BREAK_ON_EPID_ERROR(sts);

    sts = kEpidNoErr;
  } while (0);

  EpidZeroMemory(&f_str, sizeof(f_str));
  EpidZeroMemory(&t1_str, sizeof(t1_str));
  EpidZeroMemory(&t2_str, sizeof(t2_str));

  DeleteEcPoint(&B);
  DeleteEcPoint(&t);
  DeleteFfElement(&R2);
  DeleteFfElement(&a);
  DeleteFfElement(&rx);
  DeleteFfElement(&rb);
  DeleteFfElement(&t1);
  DeleteFfElement(&t2);

  return sts;
}
