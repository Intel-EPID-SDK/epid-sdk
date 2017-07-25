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

#include "epid/member/tpm/validatekey.h"

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

bool TpmIsKeyValid(TpmCtx* ctx, G1ElemStr const* A_str, FpElemStr const* x_str,
                   G1ElemStr const* h1_str, G2ElemStr const* w_str) {
  bool key_is_valid = false;
  EcPoint* t1 = NULL;
  EcPoint* t2 = NULL;
  FfElement* t3 = NULL;
  FfElement* t4 = NULL;
  EcPoint* A = NULL;
  EcPoint* h1 = NULL;
  EcPoint* w = NULL;
  BigNumStr f_str = {0};

  if (!ctx || !A_str || !x_str || !h1_str || !w_str || !ctx->epid2_params) {
    return false;
  }

  do {
    EpidStatus sts = kEpidErr;
    FiniteField* Fp = ctx->epid2_params->Fp;
    EcGroup* G1 = ctx->epid2_params->G1;
    EcGroup* G2 = ctx->epid2_params->G2;
    FiniteField* GT = ctx->epid2_params->GT;
    EcPoint* g1 = ctx->epid2_params->g1;
    EcPoint* g2 = ctx->epid2_params->g2;
    PairingState* ps_ctx = ctx->epid2_params->pairing_state;
    FfElement const* f = ctx->secret.f;

    // 2. The member computes t1 = G2.sscmExp(g2, x).
    sts = NewEcPoint(G2, &t1);
    BREAK_ON_EPID_ERROR(sts);

    sts = EcSscmExp(G2, g2, (BigNumStr const*)x_str, t1);
    BREAK_ON_EPID_ERROR(sts);

    // 3. The member computes t1 = G2.mul(t1, w).
    sts = NewEcPoint(G2, &w);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(G2, w_str, sizeof(*w_str), w);
    BREAK_ON_EPID_ERROR(sts);
    sts = EcMul(G2, t1, w, t1);
    BREAK_ON_EPID_ERROR(sts);

    // 4. The member computes t3 = pairing(A, t1).
    sts = NewFfElement(GT, &t3);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &A);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(G1, A_str, sizeof(*A_str), A);
    BREAK_ON_EPID_ERROR(sts);
    sts = Pairing(ps_ctx, A, t1, t3);
    BREAK_ON_EPID_ERROR(sts);

    // 5. The member computes t2 = G1.sscmExp(h1, f).
    sts = NewEcPoint(G1, &t2);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &h1);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(G1, h1_str, sizeof(*h1_str), h1);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, f, &f_str, sizeof(f_str));
    BREAK_ON_EPID_ERROR(sts);
    sts = EcSscmExp(G1, h1, &f_str, t2);
    BREAK_ON_EPID_ERROR(sts);

    // 6. The member computes t2 = G1.mul(t2, g1).
    sts = EcMul(G1, t2, g1, t2);
    BREAK_ON_EPID_ERROR(sts);

    // Step 7. The member computes t4 = pairing(t2, g2).
    sts = NewFfElement(GT, &t4);
    BREAK_ON_EPID_ERROR(sts);
    sts = Pairing(ps_ctx, t2, g2, t4);
    BREAK_ON_EPID_ERROR(sts);

    // 8. If GT.isEqual(t3, t4) = false, reports bad private key.
    sts = FfIsEqual(GT, t3, t4, &key_is_valid);
    if (kEpidNoErr != sts) {
      key_is_valid = false;
      BREAK_ON_EPID_ERROR(sts);
    }
  } while (0);

  EpidZeroMemory(&f_str, sizeof(f_str));

  DeleteEcPoint(&t1);
  DeleteEcPoint(&t2);
  DeleteFfElement(&t3);
  DeleteFfElement(&t4);
  DeleteEcPoint(&A);
  DeleteEcPoint(&h1);
  DeleteEcPoint(&w);

  return key_is_valid;
}
