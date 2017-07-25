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
 * \brief EpidAssemblePrivKey implementation.
 */

#include <epid/member/api.h>

#include <string.h>

#include "epid/common/src/epid2params.h"
#include "epid/common/src/memory.h"
#include "epid/member/tpm/context.h"
#include "epid/member/tpm/validatekey.h"
#include "epid/common/math/finitefield.h"
#include "epid/common/math/ecgroup.h"
#include "epid/common/types.h"

/// Handle SDK Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

// implements section 3.2.2 "Validation of Private Key" from
// Intel(R) EPID 2.0 Spec
static bool EpidIsPrivKeyInGroup(GroupPubKey const* pub_key,
                                 PrivKey const* priv_key) {
  bool result = false;
  Epid2Params_* params = NULL;
  TpmCtx* ctx = NULL;
  FfElement* x = NULL;
  EcPoint* h2 = NULL;

  if (!pub_key || !priv_key) {
    return false;
  }

  do {
    EpidStatus sts;
    sts = CreateEpid2Params(&params);
    BREAK_ON_EPID_ERROR(sts);

    // check if x and h2 are valid
    sts = NewFfElement(params->Fp, &x);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadFfElement(params->Fp, &priv_key->x, sizeof(priv_key->x), x);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(params->G1, &h2);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(params->G1, &pub_key->h2, sizeof(pub_key->h2), h2);
    BREAK_ON_EPID_ERROR(sts);

    sts = TpmCreate(NULL, NULL, params, &ctx);
    BREAK_ON_EPID_ERROR(sts);

    sts = TpmProvision(ctx, &priv_key->f);
    BREAK_ON_EPID_ERROR(sts);

    // Step 1. The member verifies that the gid in the public key matches the
    //         gid in the private key.
    if (0 != memcmp(&pub_key->gid, &priv_key->gid, sizeof(priv_key->gid))) {
      result = false;
      break;
    }

    result = TpmIsKeyValid(ctx, &priv_key->A, &priv_key->x, &pub_key->h1,
                           &pub_key->w);
  } while (0);

  TpmDelete(&ctx);
  DeleteEpid2Params(&params);
  DeleteEcPoint(&h2);
  DeleteFfElement(&x);

  return result;
}

// Implements step 8 of 3.4 Join Protocol from Intel(R) EPID 2.0 Spec.
EpidStatus EpidAssemblePrivKey(MembershipCredential const* credential,
                               FpElemStr const* f, GroupPubKey const* pub_key,
                               PrivKey* priv_key) {
  EpidStatus sts = kEpidErr;
  bool is_key_valid = false;
  PrivKey priv_key_tmp = {0};
  if (!credential || !f || !priv_key) {
    return kEpidBadArgErr;
  }
  do {
    priv_key_tmp.gid = credential->gid;
    priv_key_tmp.A = credential->A;
    priv_key_tmp.x = credential->x;
    priv_key_tmp.f = *f;

    is_key_valid = EpidIsPrivKeyInGroup(pub_key, &priv_key_tmp);
    if (!is_key_valid) {
      sts = kEpidBadArgErr;
      break;
    }

    *priv_key = priv_key_tmp;
    sts = kEpidNoErr;
  } while (0);

  EpidZeroMemory(&priv_key_tmp, sizeof(priv_key_tmp));

  return sts;
}
