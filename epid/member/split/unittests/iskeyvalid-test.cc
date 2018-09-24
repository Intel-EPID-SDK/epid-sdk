/*############################################################################
  # Copyright 2017-2018 Intel Corporation
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
/// IsKeyValid unit tests.
/*! \file  */
#include "epid/common-testhelper/epid_gtest-testhelper.h"
#include "gtest/gtest.h"

extern "C" {
#include "epid/common/src/epid2params.h"
#include "epid/member/split/src/context.h"
#include "epid/member/split/src/split_grouppubkey.h"
#include "epid/member/split/src/validatekey.h"
#include "epid/member/split/tpm2/createprimary.h"
#include "epid/member/split/tpm2/load_external.h"
}

#include "epid/common-testhelper/epid2params_wrapper-testhelper.h"
#include "epid/common-testhelper/epid_params-testhelper.h"
#include "epid/common-testhelper/errors-testhelper.h"
#include "epid/common-testhelper/prng-testhelper.h"
#include "epid/member/split/unittests/member-testhelper.h"

namespace {
const PrivKey kGrpXMemberPrivKeySha256 = {
#include "epid/common-testhelper/testdata/grp_x/member3/mprivkey_sha256_01.inc"
};

////////////////////////////////////////////////
//  EpidMemberIsKeyValid
TEST_F(EpidSplitMemberTest, EpidMemberIsKeyValidFailsGivenNullPointer) {
  // create
  Prng my_prng;
  Epid2ParamsObj epid2params;
  MemberCtxObj member(&Prng::Generate, &my_prng);
  Tpm2Key* f_handle = NULL;

  const GroupPubKey pub_key = this->kGrpXKey;
  const PrivKey priv_key = kGrpXMemberPrivKeySha256;

  MemberCtx* ctx = member;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(ctx->tpm2_ctx, kSha256, &priv_key.f, &f_handle));

  EXPECT_FALSE(EpidMemberIsKeyValid(nullptr, &priv_key.A, &priv_key.x, f_handle,
                                    &pub_key.h1, &pub_key.w));
  EXPECT_FALSE(EpidMemberIsKeyValid(member, nullptr, &priv_key.x, f_handle,
                                    &pub_key.h1, &pub_key.w));
  EXPECT_FALSE(EpidMemberIsKeyValid(member, &priv_key.A, nullptr, f_handle,
                                    &pub_key.h1, &pub_key.w));
  EXPECT_FALSE(EpidMemberIsKeyValid(member, &priv_key.A, &priv_key.x, nullptr,
                                    &pub_key.h1, &pub_key.w));
  EXPECT_FALSE(EpidMemberIsKeyValid(member, &priv_key.A, &priv_key.x, f_handle,
                                    nullptr, &pub_key.w));
  EXPECT_FALSE(EpidMemberIsKeyValid(member, &priv_key.A, &priv_key.x, f_handle,
                                    &pub_key.h1, nullptr));
}

TEST_F(EpidSplitMemberTest, EpidMemberIsKeyValidSucceedsForSha256) {
  // create
  Prng my_prng;
  Epid2ParamsObj epid2params;
  MemberCtxObj member(&Prng::Generate, &my_prng);
  Tpm2Key* f_handle = NULL;

  const GroupPubKey pub_key = this->kGrpXKey;
  const PrivKey priv_key = this->kGrpXMember3PrivKeySha256;

  MemberCtx* ctx = member;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(ctx->tpm2_ctx, kSha256, &priv_key.f, &f_handle));
  EXPECT_TRUE(EpidMemberIsKeyValid(member, &priv_key.A, &priv_key.x, f_handle,
                                   &pub_key.h1, &pub_key.w));
}

TEST_F(EpidSplitMemberTest, EpidMemberIsKeyValidFailsGivenIncorrectKeys) {
  // create
  Prng my_prng;
  Epid2ParamsObj epid2params;
  MemberCtxObj member(&Prng::Generate, &my_prng);
  Tpm2Key* f_handle = NULL;

  GroupPubKey pub_key = this->kGrpXKey;
  PrivKey priv_key = this->kGrpXMember3PrivKeySha256;

  MemberCtx* ctx = member;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(ctx->tpm2_ctx, kSha256, &priv_key.f, &f_handle));

  // check the key is valid
  EXPECT_TRUE(EpidMemberIsKeyValid(member, &priv_key.A, &priv_key.x, f_handle,
                                   &pub_key.h1, &pub_key.w));

  // check key is invalid with incorrect data
  PrivKey tmp_priv_key = priv_key;
  tmp_priv_key.A.x.data.data[31] -= 1;
  EXPECT_FALSE(EpidMemberIsKeyValid(member, &tmp_priv_key.A, &priv_key.x,
                                    f_handle, &pub_key.h1, &pub_key.w));

  tmp_priv_key = priv_key;
  tmp_priv_key.A.y.data.data[31] -= 1;
  EXPECT_FALSE(EpidMemberIsKeyValid(member, &tmp_priv_key.A, &tmp_priv_key.x,
                                    f_handle, &pub_key.h1, &pub_key.w));

  tmp_priv_key = priv_key;
  tmp_priv_key.x.data.data[31] -= 1;
  EXPECT_FALSE(EpidMemberIsKeyValid(member, &tmp_priv_key.A, &tmp_priv_key.x,
                                    f_handle, &pub_key.h1, &pub_key.w));

  GroupPubKey tmp_pub_key = pub_key;
  tmp_pub_key.h1.x.data.data[31] -= 1;
  EXPECT_FALSE(EpidMemberIsKeyValid(member, &tmp_priv_key.A, &priv_key.x,
                                    f_handle, &tmp_pub_key.h1, &tmp_pub_key.w));

  tmp_pub_key = pub_key;
  tmp_pub_key.h1.y.data.data[31] -= 1;
  EXPECT_FALSE(EpidMemberIsKeyValid(member, &tmp_priv_key.A, &priv_key.x,
                                    f_handle, &tmp_pub_key.h1, &tmp_pub_key.w));

  tmp_pub_key = pub_key;
  tmp_pub_key.w.x->data.data[31] -= 1;
  EXPECT_FALSE(EpidMemberIsKeyValid(member, &tmp_priv_key.A, &priv_key.x,
                                    f_handle, &tmp_pub_key.h1, &tmp_pub_key.w));

  tmp_pub_key = pub_key;
  tmp_pub_key.w.y->data.data[31] -= 1;
  EXPECT_FALSE(EpidMemberIsKeyValid(member, &tmp_priv_key.A, &priv_key.x,
                                    f_handle, &tmp_pub_key.h1, &tmp_pub_key.w));
}

TEST_F(EpidSplitMemberTest,
       PROTECTED_EpidMemberIsKeyValidSucceedsByCredentialForSha256_EPS0) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  MemberCtxObj member(&Prng::Generate, &my_prng);
  Tpm2Key* f_handle = NULL;

  MemberCtx* ctx = member;
  THROW_ON_EPIDERR(Tpm2CreatePrimary(ctx->tpm2_ctx, kSha256, &f_handle));
  EXPECT_TRUE(EpidMemberIsKeyValid(
      member, &this->kEps0MemberPrivateKey.A, &this->kEps0MemberPrivateKey.x,
      f_handle, &this->kEps0GroupPublicKey.h1, &this->kEps0GroupPublicKey.w));
}
}  // namespace
