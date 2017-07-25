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

/*!
 * \file
 * \brief EpidRequestJoin implementation.
 */

#include <epid/member/api.h>

#include "epid/common/src/epid2params.h"
#include "epid/member/tpm/context.h"
#include "epid/member/tpm/join.h"
#include "epid/common/types.h"
#include "epid/common/src/grouppubkey.h"
#include "epid/member/src/join_commitment.h"

/// Handle SDK Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus EpidRequestJoin(GroupPubKey const* pub_key, IssuerNonce const* ni,
                           FpElemStr const* f, BitSupplier rnd_func,
                           void* rnd_param, HashAlg hash_alg,
                           JoinRequest* join_request) {
  EpidStatus sts = kEpidErr;
  Epid2Params_* params = NULL;
  TpmCtx* ctx = NULL;
  GroupPubKey_* pub_key_ = NULL;

  if (!pub_key || !ni || !f || !rnd_func || !join_request) {
    return kEpidBadArgErr;
  }
  if (kSha256 != hash_alg && kSha384 != hash_alg && kSha512 != hash_alg &&
      kSha512_256 != hash_alg) {
    return kEpidBadArgErr;
  }

  do {
    JoinRequest request = {0};
    G1ElemStr R = {0};

    sts = CreateEpid2Params(&params);
    BREAK_ON_EPID_ERROR(sts);

    // validate public key by creating
    sts = CreateGroupPubKey(pub_key, params->G1, params->G2, &pub_key_);
    BREAK_ON_EPID_ERROR(sts);

    sts = TpmCreate(rnd_func, rnd_param, params, &ctx);
    BREAK_ON_EPID_ERROR(sts);

    sts = TpmProvision(ctx, f);
    BREAK_ON_EPID_ERROR(sts);

    sts = TpmJoinCommit(ctx, &request.F, &R);
    BREAK_ON_EPID_ERROR(sts);

    sts = HashJoinCommitment(params->Fp, hash_alg, pub_key, &request.F, &R, ni,
                             &request.c);
    BREAK_ON_EPID_ERROR(sts);

    sts = TpmJoin(ctx, &request.c, &request.s);
    BREAK_ON_EPID_ERROR(sts);

    // Step 6. The output join request is (F, c, s).
    *join_request = request;

    sts = kEpidNoErr;
  } while (0);

  DeleteGroupPubKey(&pub_key_);
  TpmDelete(&ctx);
  DeleteEpid2Params(&params);

  return sts;
}
