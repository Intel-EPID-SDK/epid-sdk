/*############################################################################
  # Copyright 2017-2019 Intel Corporation
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
/// EpidPrivateExp unit tests.
/*! \file */
#include "gtest/gtest.h"
#include "testhelper/epid_gtest-testhelper.h"

extern "C" {
#include "epid/member/split/context.h"
#include "epid/member/split/privateexp.h"
#include "epid/member/split/tpm2/createprimary.h"
}

#include "member-testhelper.h"
#include "testhelper/epid2params_wrapper-testhelper.h"
#include "testhelper/epid_params-testhelper.h"
#include "testhelper/errors-testhelper.h"
#include "testhelper/prng-testhelper.h"

namespace {

////////////////////////////////////////////////
//  EpidPrivateExp
TEST_F(EpidSplitMemberTest, EpidPrivateExpFailsGivenNullPointer) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  MemberCtxObj member(&Prng::Generate, &my_prng);
  THROW_ON_EPIDERR(EpidProvisionKey(member, &this->kGrpXKey,
                                    &this->kGrpXMember3PrivKeySha256,
                                    &this->kMemberPrecomp));
  THROW_ON_EPIDERR(EpidMemberStartup(member));

  Epid20Params params;
  EcPointObj a(&params.G1, this->kGrpXKey.h1), r(&params.G1);
  MemberCtx* ctx = member;
  EXPECT_EQ(kEpidBadArgErr, EpidPrivateExp(nullptr, a, ctx->f_handle, r));
  EXPECT_EQ(kEpidBadArgErr, EpidPrivateExp(member, nullptr, ctx->f_handle, r));
  EXPECT_EQ(kEpidBadArgErr, EpidPrivateExp(member, a, nullptr, r));
  EXPECT_EQ(kEpidBadArgErr, EpidPrivateExp(member, a, ctx->f_handle, nullptr));
}

TEST_F(EpidSplitMemberTest, EpidPrivateExpFailsArgumentsMismatch) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  MemberCtxObj member(&Prng::Generate, &my_prng);
  THROW_ON_EPIDERR(EpidProvisionKey(member, &this->kGrpXKey,
                                    &this->kGrpXMember3PrivKeySha256,
                                    &this->kMemberPrecomp));
  THROW_ON_EPIDERR(EpidMemberStartup(member));

  Epid20Params params;
  EcPointObj a(&params.G1, this->kGrpXKey.h1), r(&params.G1);
  EcPointObj g2(&params.G2, this->kGrpXKey.w);

  MemberCtx* ctx = member;
  EXPECT_EQ(kEpidBadArgErr, EpidPrivateExp(member, g2, ctx->f_handle, r));
  EXPECT_EQ(kEpidBadArgErr, EpidPrivateExp(member, a, ctx->f_handle, g2));
  EXPECT_EQ(kEpidBadArgErr, EpidPrivateExp(member, g2, ctx->f_handle, g2));
}

TEST_F(EpidSplitMemberTest,
       EpidPrivateExpSucceedsGivenValidParametersForSha256) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  MemberCtxObj member(&Prng::Generate, &my_prng);
  THROW_ON_EPIDERR(EpidProvisionKey(member, &this->kGrpXKey,
                                    &this->kGrpXMember3PrivKeySha256,
                                    &this->kMemberPrecomp));
  THROW_ON_EPIDERR(EpidMemberStartup(member));

  Epid20Params params;
  EcPointObj a(&params.G1, this->kGrpXKey.h1), r(&params.G1),
      r_expected(&params.G1);

  G1ElemStr r_str, r_expected_str;

  MemberCtx* ctx = member;
  EXPECT_EQ(kEpidNoErr, EpidPrivateExp(member, a, ctx->f_handle, r));

  THROW_ON_EPIDERR(EcExp(params.G1, a,
                         (BigNumStr const*)&this->kGrpXMember3PrivKeySha256.f,
                         r_expected));

  THROW_ON_EPIDERR(WriteEcPoint(params.G1, r, &r_str, sizeof(r_str)));
  THROW_ON_EPIDERR(WriteEcPoint(params.G1, r_expected, &r_expected_str,
                                sizeof(r_expected_str)));
  EXPECT_EQ(r_expected_str, r_str);
}

#ifndef TPM_TSS
TEST_F(EpidSplitMemberTest,
       EpidPrivateExpSucceedsGivenValidParametersForSha384) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  MemberCtxObj member(&Prng::Generate, &my_prng);
  THROW_ON_EPIDERR(EpidProvisionKey(member, &this->kGrpXKey,
                                    &this->kGrpXMember3PrivKeySha256,
                                    &this->kMemberPrecomp));
  THROW_ON_EPIDERR(EpidMemberStartup(member));

  Epid20Params params;
  EcPointObj a(&params.G1, this->kGrpXKey.h1), r(&params.G1),
      r_expected(&params.G1);

  G1ElemStr r_str, r_expected_str;

  MemberCtx* ctx = member;
  EXPECT_EQ(kEpidNoErr, EpidPrivateExp(member, a, ctx->f_handle, r));

  THROW_ON_EPIDERR(EcExp(params.G1, a,
                         (BigNumStr const*)&this->kGrpXMember3PrivKeySha256.f,
                         r_expected));

  THROW_ON_EPIDERR(WriteEcPoint(params.G1, r, &r_str, sizeof(r_str)));
  THROW_ON_EPIDERR(WriteEcPoint(params.G1, r_expected, &r_expected_str,
                                sizeof(r_expected_str)));
  EXPECT_EQ(r_expected_str, r_str);
}
#endif

TEST_F(EpidSplitMemberTest,
       PROTECTED_EpidPrivateExpSucceedsByCredentialForSha256_EPS0) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  MemberCtxObj member(&Prng::Generate, &my_prng);
  Tpm2Key* f_handle = NULL;
  BigNumStr const f_str = {
      0x25, 0xa9, 0xa1, 0x86, 0xd5, 0x46, 0xd1, 0x50, 0xf8, 0xb0, 0x14,
      0x75, 0x60, 0x55, 0x67, 0x81, 0x39, 0xd2, 0x74, 0x94, 0x7c, 0x41,
      0xaf, 0x7c, 0xa7, 0xa8, 0x51, 0xd9, 0xf8, 0x1a, 0x55, 0xcb,
  };

  Epid20Params params;
  EcPointObj a(&params.G1, this->kGrpXKey.h1), r(&params.G1),
      r_expected(&params.G1);

  G1ElemStr r_str, r_expected_str;

  MemberCtx* ctx = member;
  THROW_ON_EPIDERR(Tpm2CreatePrimary(ctx->tpm2_ctx, kSha256, &f_handle));
  EXPECT_EQ(kEpidNoErr, EpidPrivateExp(member, a, f_handle, r));

  THROW_ON_EPIDERR(EcExp(params.G1, a, (BigNumStr const*)&f_str, r_expected));

  THROW_ON_EPIDERR(WriteEcPoint(params.G1, r, &r_str, sizeof(r_str)));
  THROW_ON_EPIDERR(WriteEcPoint(params.G1, r_expected, &r_expected_str,
                                sizeof(r_expected_str)));
  EXPECT_EQ(r_expected_str, r_str);
}

}  // namespace
