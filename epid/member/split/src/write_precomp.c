/*############################################################################
  # Copyright 2016-2019 Intel Corporation
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
/// EpidMemberWritePrecomp implementation.
/*! \file */
#define EXPORT_EPID_APIS
#include <epid/member/api.h>

#include <string.h>

#include "common/epid2params.h"
#include "common/gid_parser.h"
#include "epid/member/split/precomp.h"
#include "epid/member/split/split_grouppubkey.h"
#include "epid/types.h"

/// Handle SDK Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus EPID_MEMBER_API EpidMemberWritePrecomp(
    GroupPubKey const* pub_key, MembershipCredential const* credential,
    MemberPrecomp* precomp_str) {
  EpidStatus sts = kEpidErr;
  Epid2Params_* epid2_params = NULL;

  if (!pub_key || !credential || !precomp_str) {
    return kEpidBadArgErr;
  }
  if (memcmp(&pub_key->gid, &credential->gid, sizeof(GroupId))) {
    return kEpidBadArgErr;
  }

  do {
    GroupPubKey split_pub_key = {0};
    HashAlg hash_alg = kInvalidHashAlg;
    sts = EpidParseHashAlg(&pub_key->gid, &hash_alg);
    BREAK_ON_EPID_ERROR(sts);
    sts = CreateEpid2Params(&epid2_params);
    BREAK_ON_EPID_ERROR(sts);
    sts = EpidComputeSplitGroupPubKey(epid2_params->G1, pub_key, hash_alg,
                                      &split_pub_key);
    BREAK_ON_EPID_ERROR(sts);

    sts = PrecomputeMemberPairing(epid2_params, &split_pub_key, &credential->A,
                                  precomp_str);
    BREAK_ON_EPID_ERROR(sts);

    sts = kEpidNoErr;
  } while (0);
  DeleteEpid2Params(&epid2_params);
  return sts;
}
