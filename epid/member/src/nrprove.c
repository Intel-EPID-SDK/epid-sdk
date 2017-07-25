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
 * \brief EpidNrProve implementation.
 */
#include <epid/member/api.h>

#include <stddef.h>
#include <stdint.h>

#include "epid/common/stdtypes.h"
#include "epid/member/src/context.h"
#include "epid/common/types.h"
#include "epid/common/src/epid2params.h"
#include "epid/member/tpm/nrprove.h"
#include "epid/member/src/nrprove_commitment.h"

/// Handle SDK Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

static bool IsIdentity(G1ElemStr const* elem_str) {
  unsigned char* bytes = (unsigned char*)elem_str;
  if (!bytes) {
    return false;
  } else {
    size_t i = 0;
    for (i = 0; i < sizeof(*elem_str); i++) {
      if (0 != bytes[i]) return false;
    }
  }
  return true;
}

EpidStatus EpidNrProve(MemberCtx const* ctx, void const* msg, size_t msg_len,
                       BasicSignature const* sig, SigRlEntry const* sigrl_entry,
                       NrProof* proof) {
  EpidStatus sts = kEpidErr;

  if (!ctx || (0 != msg_len && !msg) || !sig || !sigrl_entry || !proof)
    return kEpidBadArgErr;
  if (!ctx->epid2_params) return kEpidBadArgErr;

  do {
    NrProveCommitOutput commit_out = {0};
    FiniteField* Fp = ctx->epid2_params->Fp;
    FpElemStr c_str = {0};

    sts = TpmNrProveCommit(ctx->tpm_ctx, &sig->B, &sig->K, sigrl_entry,
                           &commit_out);
    BREAK_ON_EPID_ERROR(sts);

    sts = HashNrProveCommitment(Fp, ctx->hash_alg, &sig->B, &sig->K,
                                sigrl_entry, &commit_out, msg, msg_len, &c_str);
    BREAK_ON_EPID_ERROR(sts);

    // 10. The member outputs sigma = (T, c, smu, snu), a non-revoked
    //     proof. If G1.is_identity(T) = true, the member also outputs
    //     "failed".
    sts = TpmNrProve(ctx->tpm_ctx, &c_str, &proof->smu, &proof->snu);
    BREAK_ON_EPID_ERROR(sts);

    proof->T = commit_out.T;
    proof->c = c_str;

    if (IsIdentity(&proof->T)) {
      sts = kEpidSigRevokedInSigRl;
      BREAK_ON_EPID_ERROR(sts);
    }

    sts = kEpidNoErr;
  } while (0);

  return sts;
}
