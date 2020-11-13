/*############################################################################
# Copyright 2018-2020 Intel Corporation
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
#include <string.h>

#include "epid/member/api.h"

#include "epid/member/tiny/native_types.h"
#include "epid/member/tiny/serialize.h"
#include "epid/member/tiny/validate.h"
#include "epid/types.h"
#include "tinymath/efq.h"
#include "tinymath/fq.h"
#include "tinymath/mathtypes.h"
#include "tinymath/pairing.h"
#include "tinymath/serialize.h"

static EccPointFq2 const epid20_g2 = {
    {{{{0xBF282394, 0xF6021343, 0x3D32470E, 0xD25D5268, 0x743CCF22, 0x21670413,
        0x4AA3DA05, 0xE20171C5}}},
     {{{0xBAA189BE, 0x7DF7B212, 0x289653E2, 0x43433BF6, 0x4FBB5656, 0x46CCDC25,
        0x53A85A80, 0x592D1EF6}}}},
    {{{{0xDD2335AE, 0x414DB822, 0x4D916838, 0x55E8B59A, 0x312826BD, 0xC621E703,
        0x51FFD350, 0xAE60A4E7}}},
     {{{0x51B92421, 0x2C90FE89, 0x9093D613, 0x2CDC6181, 0x7645E253, 0xF80274F8,
        0x89AFE5AD, 0x1AB442F9}}}}};

EpidStatus EPID_MEMBER_API EpidMemberWritePrecomp(
    GroupPubKey const* pub_key, MembershipCredential const* credential,
    MemberPrecomp* precomp_str) {
  EpidStatus sts = kEpidErr;
  NativeGroupPubKey native_pub_key;
  EccPointFq A;
  PairingState pairing;
  Fq12Elem res;

  if (!pub_key || !credential || !precomp_str) {
    return kEpidBadArgErr;
  }
  if (memcmp(&pub_key->gid, &credential->gid, sizeof(GroupId))) {
    return kEpidBadArgErr;
  }

  do {
    GroupPubKeyDeserialize(&native_pub_key, pub_key);
    EFqDeserialize(&A, &credential->A);
    if (!GroupPubKeyIsInRange(&native_pub_key) || !EFqOnCurve(&A)) {
      sts = kEpidBadArgErr;
      break;
    }

    PairingInit(&pairing);
    PairingCompute(&res, &A, &epid20_g2, &pairing);
    Fq12Serialize((Fq12ElemStr*)&precomp_str->ea2, &res);
    PairingCompute(&res, &native_pub_key.h1, &epid20_g2, &pairing);
    Fq12Serialize((Fq12ElemStr*)&precomp_str->e12, &res);
    PairingCompute(&res, &native_pub_key.h2, &epid20_g2, &pairing);
    Fq12Serialize((Fq12ElemStr*)&precomp_str->e22, &res);
    PairingCompute(&res, &native_pub_key.h2, &native_pub_key.w, &pairing);
    Fq12Serialize((Fq12ElemStr*)&precomp_str->e2w, &res);
    sts = kEpidNoErr;
  } while (0);

  // Zero sensitive stack variables
  FqClear(&A.x);
  FqClear(&A.y);

  return sts;
}
