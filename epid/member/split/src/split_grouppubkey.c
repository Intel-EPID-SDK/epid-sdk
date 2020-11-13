/*############################################################################
  # Copyright 2018-2019 Intel Corporation
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
/// Split member group public key helper implementation
/*! \file */

#include "epid/member/split/split_grouppubkey.h"

#include "common/epid2params.h"
#include "ippmath/ecgroup.h"

/// Handle Intel(R) EPID Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus EpidComputeSplitGroupPubKey(EcGroup const* g,
                                       GroupPubKey const* pub_key,
                                       HashAlg hash_alg,
                                       GroupPubKey* split_pub_key) {
  EcPoint* h1_prime = NULL;
  EpidStatus sts = kEpidNoErr;

  if (!g || !pub_key || !split_pub_key) {
    return kEpidBadArgErr;
  }
  if (kSha256 != hash_alg && kSha384 != hash_alg && kSha512 != hash_alg &&
      kSha512_256 != hash_alg) {
    return kEpidHashAlgorithmNotSupported;
  }

  *split_pub_key = *pub_key;

  do {
    sts = NewEcPoint(g, &h1_prime);
    BREAK_ON_EPID_ERROR(sts);
    // validate h1
    sts = ReadEcPoint((EcGroup*)g, &pub_key->h1, sizeof(pub_key->h1), h1_prime);
    BREAK_ON_EPID_ERROR(sts);
    // create h1' from h1
    sts = EcHash((EcGroup*)g, &pub_key->h1, sizeof(pub_key->h1), hash_alg,
                 h1_prime, NULL);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteEcPoint((EcGroup*)g, h1_prime, &split_pub_key->h1,
                       sizeof(split_pub_key->h1));
    BREAK_ON_EPID_ERROR(sts);
  } while (0);

  DeleteEcPoint(&h1_prime);
  return sts;
}
