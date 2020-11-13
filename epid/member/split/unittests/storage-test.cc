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

/*!
 * \file
 * \brief Member credentials storage helper API unit tests.
 */
#include <cstring>

#include "gtest/gtest.h"
#include "testhelper/epid_gtest-testhelper.h"

#include "tpm2-testhelper.h"
#include "member-testhelper.h"
#include "testhelper/epid2params_wrapper-testhelper.h"
#include "testhelper/errors-testhelper.h"
#include "testhelper/prng-testhelper.h"

extern "C" {
#include "epid/member/split/storage.h"
#include "epid/member/split/tpm2/nv.h"
}

namespace {

TEST_F(EpidSplitMemberTest, NvWriteMembershipCredentialFailsGivenNullPointer) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, nullptr, epid2params);

  GroupPubKey const pub_key = this->kGrpXKey;
  // PrivKey can be trimmed to MembershipCredential
  MembershipCredential const credential =
      *(MembershipCredential*)&this->kGrpXMember3PrivKeySha256;

  EXPECT_EQ(kEpidBadArgErr,
            EpidNvWriteMembershipCredential(nullptr, &pub_key, &credential));
  EXPECT_EQ(kEpidBadArgErr,
            EpidNvWriteMembershipCredential(tpm, nullptr, &credential));
}

TEST_F(EpidSplitMemberTest, NvReadMembershipCredentialFailsGivenNoCredentials) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, nullptr, epid2params);

  // clear NV slot
  EpidNvClearMembershipCredential(tpm);

  GroupPubKey pub_key = this->kGrpXKey;
  // PrivKey can be trimmed to MembershipCredential
  MembershipCredential credential =
      *(MembershipCredential*)&this->kGrpXMember3PrivKeySha256;

  EXPECT_EQ(kEpidBadArgErr,
            EpidNvReadMembershipCredential(tpm, &pub_key, &credential));
}

TEST_F(EpidSplitMemberTest, NvReadMembershipCredentialFailsGivenNullPointer) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, nullptr, epid2params);

  GroupPubKey pub_key = this->kGrpXKey;
  // PrivKey can be trimmed to MembershipCredential
  MembershipCredential credential =
      *(MembershipCredential*)&this->kGrpXMember3PrivKeySha256;

  // write credentials
  EXPECT_EQ(kEpidNoErr,
            EpidNvWriteMembershipCredential(tpm, &pub_key, &credential));

  EXPECT_EQ(kEpidBadArgErr,
            EpidNvReadMembershipCredential(nullptr, &pub_key, &credential));
  EXPECT_EQ(kEpidBadArgErr,
            EpidNvReadMembershipCredential(tpm, nullptr, &credential));
  EXPECT_EQ(kEpidBadArgErr,
            EpidNvReadMembershipCredential(tpm, &pub_key, nullptr));
}

TEST_F(EpidSplitMemberTest, WrittenMembershipCredentialCanBeRead) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, nullptr, epid2params);

  GroupPubKey pub_key = this->kGrpXKey;
  // PrivKey can be trimmed to MembershipCredential
  MembershipCredential credential_expected =
      *(MembershipCredential*)&this->kGrpXMember3PrivKeySha256;
  MembershipCredential credential;

  // write credentials
  EXPECT_EQ(kEpidNoErr, EpidNvWriteMembershipCredential(tpm, &pub_key,
                                                        &credential_expected));

  // read credentials
  EXPECT_EQ(kEpidNoErr,
            EpidNvReadMembershipCredential(tpm, &pub_key, &credential));

  EXPECT_EQ(this->kGrpXKey, pub_key);
  EXPECT_EQ(credential_expected, credential);
}

}  // namespace
