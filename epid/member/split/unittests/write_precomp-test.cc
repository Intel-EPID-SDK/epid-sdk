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
void set_gid_hashalg(GroupId* id, HashAlg hashalg) {
  id->data[1] = (id->data[1] & 0xf0) | (hashalg & 0x0f);
}

// local constant for Write Precomp tests. This can be hoisted later if needed
// avoids cpplint warning about multiple includes.
static const MembershipCredential kGrpXMember3Sha256Credential = {
#include "testhelper/testdata/grp_x/member3/splitmembercredential_grpx_member3_sha256_01.inc"
};
static const MembershipCredential kGrpXMember3Sha512Credential = {
#include "testhelper/testdata/grp_x/member3/splitmembercredential_grpx_member3_sha512_01.inc"
};
static const MembershipCredential kGrpXMember3Sha384Credential = {
#include "testhelper/testdata/grp_x/member3/splitmembercredential_grpx_member3_sha384_01.inc"
};
static const MembershipCredential kGrpXMember3Sha512256Credential = {
#include "testhelper/testdata/grp_x/member3/splitmembercredential_grpx_member3_sha512_256_01.inc"
};
const MemberPrecomp kGrpXMember3Sha256Precomp = {
#include "testhelper/testdata/grp_x/member3/splitprecomp_grpx_member3_sha256_01.inc"
};
const MemberPrecomp kGrpXMember3Sha512Precomp = {
#include "testhelper/testdata/grp_x/member3/splitprecomp_grpx_member3_sha512_01.inc"
};
const MemberPrecomp kGrpXMember3Sha384Precomp = {
#include "testhelper/testdata/grp_x/member3/splitprecomp_grpx_member3_sha384_01.inc"
};
const MemberPrecomp kGrpXMember3Sha512256Precomp = {
#include "testhelper/testdata/grp_x/member3/splitprecomp_grpx_member3_sha512_256_01.inc"
};

//////////////////////////////////////////////////////////////////////////
// EpidMemberWritePrecomp
TEST_F(EpidSplitMemberTest, MemberWritePrecompFailsGivenNullPointer) {
  MemberPrecomp member_precomp = {0};
  MembershipCredential credential;
  credential.gid = this->kGrpXMember3PrivKeySha256.gid;
  credential.A = this->kGrpXMember3PrivKeySha256.A;
  credential.x = this->kGrpXMember3PrivKeySha256.x;
  EXPECT_EQ(kEpidBadArgErr,
            EpidMemberWritePrecomp(nullptr, &credential, &member_precomp));
  EXPECT_EQ(kEpidBadArgErr,
            EpidMemberWritePrecomp(&this->kGrpXKey, nullptr, &member_precomp));
  EXPECT_EQ(kEpidBadArgErr,
            EpidMemberWritePrecomp(&this->kGrpXKey, &credential, nullptr));
}

TEST_F(EpidSplitMemberTest, MemberWritePrecompFailsGivenInvalidCredential) {
  MemberPrecomp member_precomp = {0};
  MembershipCredential invalid_credential;
  invalid_credential.gid = this->kGrpXMember3PrivKeySha256.gid;
  invalid_credential.A = this->kGrpXMember3PrivKeySha256.A;
  invalid_credential.x = this->kGrpXMember3PrivKeySha256.x;

  FqElemStr invalid_fq = {0xff};
  invalid_credential.A.x = invalid_fq;
  EXPECT_EQ(kEpidBadArgErr,
            EpidMemberWritePrecomp(&this->kGrpXKey, &invalid_credential,
                                   &member_precomp));
}

TEST_F(EpidSplitMemberTest, MemberWritePrecompFailsGivenInvalidPubKey) {
  MemberPrecomp member_precomp = {0};
  MembershipCredential credential;
  credential.gid = this->kGrpXMember3PrivKeySha256.gid;
  credential.A = this->kGrpXMember3PrivKeySha256.A;
  credential.x = this->kGrpXMember3PrivKeySha256.x;

  GroupPubKey invalid_pub_key = this->kGrpXKey;
  FqElemStr invalid_fq = {0xff};
  invalid_pub_key.h1.x = invalid_fq;
  EXPECT_EQ(
      kEpidBadArgErr,
      EpidMemberWritePrecomp(&invalid_pub_key, &credential, &member_precomp));
}

TEST_F(EpidSplitMemberTest, MemberWritePrecompFailsGivenMismatchedGroups) {
  MemberPrecomp member_precomp = {0};
  MembershipCredential credential;
  credential.gid = this->kGrpXMember3PrivKeySha256.gid;
  credential.A = this->kGrpXMember3PrivKeySha256.A;
  credential.x = this->kGrpXMember3PrivKeySha256.x;
  EXPECT_EQ(kEpidBadArgErr, EpidMemberWritePrecomp(&this->kGrpYKey, &credential,
                                                   &member_precomp));
}

TEST_F(EpidSplitMemberTest, MemberWritePrecompFailsGivenUnsupportedHashAlg) {
  MemberPrecomp member_precomp = {0};
  GroupPubKey pub_key = this->kGrpXKey;
  MembershipCredential credential;
  credential.gid = this->kGrpXMember3PrivKeySha256.gid;
  credential.A = this->kGrpXMember3PrivKeySha256.A;
  credential.x = this->kGrpXMember3PrivKeySha256.x;

  set_gid_hashalg(&pub_key.gid, kInvalidHashAlg);
  set_gid_hashalg(&credential.gid, kInvalidHashAlg);
  EXPECT_EQ(kEpidHashAlgorithmNotSupported,
            EpidMemberWritePrecomp(&pub_key, &credential, &member_precomp));
  set_gid_hashalg(&pub_key.gid, kSha3_256);
  set_gid_hashalg(&credential.gid, kSha3_256);
  EXPECT_EQ(kEpidHashAlgorithmNotSupported,
            EpidMemberWritePrecomp(&pub_key, &credential, &member_precomp));
  set_gid_hashalg(&pub_key.gid, kSha3_384);
  set_gid_hashalg(&credential.gid, kSha3_384);
  EXPECT_EQ(kEpidHashAlgorithmNotSupported,
            EpidMemberWritePrecomp(&pub_key, &credential, &member_precomp));
  set_gid_hashalg(&pub_key.gid, kSha3_512);
  set_gid_hashalg(&credential.gid, kSha3_512);
  EXPECT_EQ(kEpidHashAlgorithmNotSupported,
            EpidMemberWritePrecomp(&pub_key, &credential, &member_precomp));
}

TEST_F(EpidSplitMemberTest,
       MemberWritePrecompSucceedGivenValidArgumentsForSha256) {
  MemberPrecomp member_precomp = {0};
  GroupPubKey pub_key = this->kGrpXKey;
  MembershipCredential credential = kGrpXMember3Sha256Credential;
  EXPECT_EQ(kEpidNoErr,
            EpidMemberWritePrecomp(&pub_key, &credential, &member_precomp));
  EXPECT_EQ(kGrpXMember3Sha256Precomp, member_precomp);
}

TEST_F(EpidSplitMemberTest,
       MemberWritePrecompSucceedGivenValidArgumentsForSha384) {
  MemberPrecomp member_precomp = {0};
  GroupPubKey pub_key = this->kGrpXKey;
  MembershipCredential credential = kGrpXMember3Sha384Credential;
  set_gid_hashalg(&pub_key.gid, kSha384);
  set_gid_hashalg(&credential.gid, kSha384);
  EXPECT_EQ(kEpidNoErr,
            EpidMemberWritePrecomp(&pub_key, &credential, &member_precomp));
  EXPECT_EQ(kGrpXMember3Sha384Precomp, member_precomp);
}

TEST_F(EpidSplitMemberTest,
       MemberWritePrecompSucceedGivenValidArgumentsForSha512) {
  MemberPrecomp member_precomp = {0};
  GroupPubKey pub_key = this->kGrpXKey;
  MembershipCredential credential = kGrpXMember3Sha512Credential;
  set_gid_hashalg(&pub_key.gid, kSha512);
  set_gid_hashalg(&credential.gid, kSha512);
  EXPECT_EQ(kEpidNoErr,
            EpidMemberWritePrecomp(&pub_key, &credential, &member_precomp));
  EXPECT_EQ(kGrpXMember3Sha512Precomp, member_precomp);
}

TEST_F(EpidSplitMemberTest,
       MemberWritePrecompSucceedGivenValidArgumentsShaFor512_256) {
  MemberPrecomp member_precomp = {0};
  GroupPubKey pub_key = this->kGrpXKey;
  MembershipCredential credential = kGrpXMember3Sha512256Credential;
  set_gid_hashalg(&pub_key.gid, kSha512_256);
  set_gid_hashalg(&credential.gid, kSha512_256);
  EXPECT_EQ(kEpidNoErr,
            EpidMemberWritePrecomp(&pub_key, &credential, &member_precomp));
  EXPECT_EQ(kGrpXMember3Sha512256Precomp, member_precomp);
}
}  // namespace
