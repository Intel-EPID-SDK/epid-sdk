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
/// TPM signing implementation
/*! \file */

#include "epid/member/tpm/sign.h"

#include "epid/common/src/epid2params.h"
#include "epid/common/math/finitefield.h"
#include "epid/common/math/ecgroup.h"
#include "epid/member/tpm/src/types.h"
#include "epid/member/tpm/src/presig-internal.h"
#include "epid/common/src/memory.h"

/// Handle Intel(R) EPID Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus TpmSignCommit(TpmCtx* ctx, G1ElemStr const* B_in_str,
                         SignCommitOutput* commit_out) {
  EpidStatus sts = kEpidErr;

  EcPoint* B = NULL;
  EcPoint* t = NULL;  // temp value in G1
  BigNumStr f_str = {0};
  PreComputedSignature curr_presig = {0};

  if (!ctx || !commit_out || !ctx->epid2_params) {
    return kEpidBadArgErr;
  }

  do {
    FiniteField* Fp = ctx->epid2_params->Fp;
    EcGroup* G1 = ctx->epid2_params->G1;
    FfElement const* f = ctx->secret.f;
    FfElement* a = ctx->secret.a;
    FfElement* b = ctx->secret.b;
    FfElement* rx = ctx->secret.rx;
    FfElement* rf = ctx->secret.rf;
    FfElement* ra = ctx->secret.ra;
    FfElement* rb = ctx->secret.rb;

    sts = NewEcPoint(G1, &B);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &t);
    BREAK_ON_EPID_ERROR(sts);

    sts = TpmGetPreSig(ctx, &curr_presig);
    BREAK_ON_EPID_ERROR(sts);

    // 3.  If the pre-computed signature pre-sigma exists, the member
    //     loads (B, K, T, a, b, rx, rf, ra, rb, R1, R2) from
    //     pre-sigma. Refer to Section 4.4 for the computation of
    //     these values.
    sts = ReadFfElement(Fp, &curr_presig.a, sizeof(curr_presig.a), a);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadFfElement(Fp, &curr_presig.b, sizeof(curr_presig.b), b);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadFfElement(Fp, &curr_presig.rx, sizeof(curr_presig.rx), rx);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadFfElement(Fp, &curr_presig.rf, sizeof(curr_presig.rf), rf);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadFfElement(Fp, &curr_presig.ra, sizeof(curr_presig.ra), ra);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadFfElement(Fp, &curr_presig.rb, sizeof(curr_presig.rb), rb);
    BREAK_ON_EPID_ERROR(sts);

    // If the basename is provided, use it, otherwise use presig B
    if (B_in_str) {
      sts = ReadEcPoint(G1, B_in_str, sizeof(*B_in_str), B);
      BREAK_ON_EPID_ERROR(sts);
      commit_out->B = *B_in_str;
    } else {
      sts = ReadEcPoint(G1, &curr_presig.B, sizeof(curr_presig.B), B);
      BREAK_ON_EPID_ERROR(sts);
      commit_out->B = curr_presig.B;
    }

    //   b. The member computes K = G1.sscmExp(B, f), where B comes
    //      from step a.
    sts = WriteFfElement(Fp, f, &f_str, sizeof(f_str));
    BREAK_ON_EPID_ERROR(sts);
    sts = EcSscmExp(G1, B, &f_str, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteEcPoint(G1, t, &commit_out->K, sizeof(commit_out->K));
    BREAK_ON_EPID_ERROR(sts);

    //   c. The member computes R1 = G1.sscmExp(B, rf), where B comes
    //      from step a.
    sts = EcSscmExp(G1, B, (const BigNumStr*)&curr_presig.rf, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteEcPoint(G1, t, &commit_out->R1, sizeof(commit_out->R1));
    BREAK_ON_EPID_ERROR(sts);

    commit_out->T = curr_presig.T;
    commit_out->R2 = curr_presig.R2;
    ctx->secret.sign_pending = true;

    sts = kEpidNoErr;
  } while (0);

  EpidZeroMemory(&f_str, sizeof(f_str));
  EpidZeroMemory(&curr_presig, sizeof(curr_presig));

  DeleteEcPoint(&B);
  DeleteEcPoint(&t);

  return sts;
}

EpidStatus TpmSign(TpmCtx* ctx, FpElemStr const* c_str, FpElemStr* sx_str,
                   FpElemStr* sf_str, FpElemStr* sa_str, FpElemStr* sb_str) {
  EpidStatus sts = kEpidErr;

  FfElement* t = NULL;  // temporary multiplication sts
  FfElement* c = NULL;

  if (!ctx || !c_str || !sx_str || !sf_str || !sa_str || !sb_str ||
      !ctx->epid2_params) {
    return kEpidBadArgErr;
  }

  if (!ctx->secret.sign_pending) {
    return kEpidOutOfSequenceError;
  }

  do {
    FiniteField* Fp = ctx->epid2_params->Fp;
    FfElement const* a = ctx->secret.a;
    FfElement const* b = ctx->secret.b;
    FfElement const* rx = ctx->secret.rx;
    FfElement const* rf = ctx->secret.rf;
    FfElement const* ra = ctx->secret.ra;
    FfElement const* rb = ctx->secret.rb;

    FfElement const* x = ctx->x;
    FfElement const* f = ctx->secret.f;

    sts = NewFfElement(Fp, &t);
    BREAK_ON_EPID_ERROR(sts);

    sts = NewFfElement(Fp, &c);
    BREAK_ON_EPID_ERROR(sts);

    sts = ReadFfElement(Fp, c_str, sizeof(*c_str), c);
    BREAK_ON_EPID_ERROR(sts);

    // 7.  The member computes sx = (rx + c * x) mod p.
    sts = FfMul(Fp, c, x, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfAdd(Fp, rx, t, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, t, sx_str, sizeof(*sx_str));
    BREAK_ON_EPID_ERROR(sts);

    // 8.  The member computes sf = (rf + c * f) mod p.
    sts = FfMul(Fp, c, f, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfAdd(Fp, rf, t, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, t, sf_str, sizeof(*sf_str));
    BREAK_ON_EPID_ERROR(sts);

    // 9.  The member computes sa = (ra + c * a) mod p.
    sts = FfMul(Fp, c, a, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfAdd(Fp, ra, t, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, t, sa_str, sizeof(*sa_str));
    BREAK_ON_EPID_ERROR(sts);

    // 10. The member computes sb = (rb + c * b) mod p.
    sts = FfMul(Fp, c, b, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfAdd(Fp, rb, t, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, t, sb_str, sizeof(*sb_str));
    BREAK_ON_EPID_ERROR(sts);

    ctx->secret.sign_pending = false;

    sts = kEpidNoErr;
  } while (0);

  DeleteFfElement(&t);
  DeleteFfElement(&c);

  return sts;
}
