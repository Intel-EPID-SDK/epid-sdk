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

/*!
 * \file
 * \brief EpidMemberWritePrecomp unit tests.
 */
#include <cstring>

#include "gtest/gtest.h"
#include "testhelper/epid_gtest-testhelper.h"

extern "C" {
#include "epid/member/api.h"
}

#include "member-testhelper.h"

bool operator==(MemberPrecomp const& lhs, MemberPrecomp const& rhs) {
  return 0 == std::memcmp(&lhs, &rhs, sizeof(lhs));
}

namespace {
//////////////////////////////////////////////////////////////////////////
// EpidMemberWritePrecomp
TEST_F(EpidMemberTest, MemberWritePrecompFailsGivenNullPointer) {
  MemberPrecomp member_precomp = {0};
  MembershipCredential credential;
  credential.gid = this->kMemberPrivateKey.gid;
  credential.A = this->kMemberPrivateKey.A;
  credential.x = this->kMemberPrivateKey.x;
  EXPECT_EQ(kEpidBadArgErr,
            EpidMemberWritePrecomp(nullptr, &credential, &member_precomp));
  EXPECT_EQ(kEpidBadArgErr, EpidMemberWritePrecomp(&this->kGroupPublicKey,
                                                   nullptr, &member_precomp));
  EXPECT_EQ(kEpidBadArgErr, EpidMemberWritePrecomp(&this->kGroupPublicKey,
                                                   &credential, nullptr));
}

TEST_F(EpidMemberTest, MemberWritePrecompFailsGivenInvalidCredential) {
  MemberPrecomp member_precomp = {0};
  MembershipCredential invalid_credential;
  invalid_credential.gid = this->kMemberPrivateKey.gid;
  invalid_credential.A = this->kMemberPrivateKey.A;
  invalid_credential.x = this->kMemberPrivateKey.x;

  FqElemStr invalid_fq = {0xff};
  invalid_credential.A.x = invalid_fq;
  EXPECT_EQ(kEpidBadArgErr,
            EpidMemberWritePrecomp(&this->kGroupPublicKey, &invalid_credential,
                                   &member_precomp));
}

TEST_F(EpidMemberTest, MemberWritePrecompFailsGivenInvalidPubKey) {
  MemberPrecomp member_precomp = {0};
  MembershipCredential credential;
  credential.gid = this->kMemberPrivateKey.gid;
  credential.A = this->kMemberPrivateKey.A;
  credential.x = this->kMemberPrivateKey.x;

  GroupPubKey invalid_pub_key = this->kGroupPublicKey;
  FqElemStr invalid_fq = {0xff};
  invalid_pub_key.h1.x = invalid_fq;
  EXPECT_EQ(
      kEpidBadArgErr,
      EpidMemberWritePrecomp(&invalid_pub_key, &credential, &member_precomp));
}

TEST_F(EpidMemberTest, MemberWritePrecompFailsGivenMismatchedGroups) {
  MemberPrecomp member_precomp = {0};
  MembershipCredential credential;
  credential.gid = this->kMemberPrivateKey.gid;
  credential.A = this->kMemberPrivateKey.A;
  credential.x = this->kMemberPrivateKey.x;
  EXPECT_EQ(kEpidBadArgErr, EpidMemberWritePrecomp(&this->kGrpXKey, &credential,
                                                   &member_precomp));
}

TEST_F(EpidMemberTest, MemberWritePrecompSucceedGivenValidArguments) {
  MemberPrecomp member_precomp = {0};
  MembershipCredential credential;
  credential.gid = this->kMemberPrivateKey.gid;
  credential.A = this->kMemberPrivateKey.A;
  credential.x = this->kMemberPrivateKey.x;
  EXPECT_EQ(kEpidNoErr, EpidMemberWritePrecomp(&this->kGroupPublicKey,
                                               &credential, &member_precomp));
  EXPECT_EQ(this->kMemberPrecomp, member_precomp);
}

}  // namespace
