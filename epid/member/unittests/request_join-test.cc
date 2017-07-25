/*############################################################################
  # Copyright 2016-2017 Intel Corporation
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
 * \brief RequestJoin unit tests.
 */

#include <memory>
#include "epid/common-testhelper/epid_gtest-testhelper.h"
#include "gtest/gtest.h"

extern "C" {
#include "epid/member/api.h"
#include "epid/common/math/ecgroup.h"
#include "epid/common/math/finitefield.h"
#include "epid/common/src/epid2params.h"
}

#include "epid/member/unittests/member-testhelper.h"
#include "epid/common-testhelper/prng-testhelper.h"
#include "epid/common-testhelper/finite_field_wrapper-testhelper.h"
#include "epid/common-testhelper/ffelement_wrapper-testhelper.h"
#include "epid/common-testhelper/epid_params-testhelper.h"
#include "epid/common-testhelper/ecgroup_wrapper-testhelper.h"
#include "epid/common-testhelper/ecpoint_wrapper-testhelper.h"

namespace {

// local constant for RequestJoin tests. This can be hoisted later if needed
// avoids cpplint warning about multiple includes.
const GroupPubKey kPubKey = {
#include "epid/common-testhelper/testdata/grp01/gpubkey.inc"
};

TEST_F(EpidMemberTest, RequestJoinFailsGivenNullParameters) {
  GroupPubKey pub_key = kPubKey;
  IssuerNonce ni;
  FpElemStr f;
  Prng prng;
  BitSupplier rnd_func = Prng::Generate;
  void* rnd_param = &prng;
  JoinRequest join_request;
  EXPECT_EQ(kEpidBadArgErr, EpidRequestJoin(nullptr, &ni, &f, rnd_func,
                                            rnd_param, kSha256, &join_request));
  EXPECT_EQ(kEpidBadArgErr, EpidRequestJoin(&pub_key, nullptr, &f, rnd_func,
                                            rnd_param, kSha256, &join_request));
  EXPECT_EQ(kEpidBadArgErr, EpidRequestJoin(&pub_key, &ni, nullptr, rnd_func,
                                            rnd_param, kSha256, &join_request));
  EXPECT_EQ(kEpidBadArgErr, EpidRequestJoin(&pub_key, &ni, &f, rnd_func,
                                            rnd_param, kSha256, nullptr));
  EXPECT_EQ(kEpidBadArgErr, EpidRequestJoin(&pub_key, &ni, &f, nullptr,
                                            rnd_param, kSha256, &join_request));
}

TEST_F(EpidMemberTest, RequestJoinFailsGivenInvalidGroupKey) {
  Prng prng;
  BitSupplier rnd_func = Prng::Generate;
  void* rnd_param = &prng;
  JoinRequest join_request;
  GroupPubKey pub_key = kPubKey;
  FpElemStr f = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
  };
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  pub_key.h1.x.data.data[15] = 0xff;
  Epid20Params params;
  EcPointObj pt(&params.G1);
  ASSERT_NE(kEpidNoErr, ReadEcPoint(params.G1, (uint8_t*)&pub_key.h1,
                                    sizeof(pub_key.h1), pt));
  EXPECT_EQ(kEpidBadArgErr, EpidRequestJoin(&pub_key, &ni, &f, rnd_func,
                                            rnd_param, kSha256, &join_request));
}

TEST_F(EpidMemberTest, RequestJoinFailsGivenInvalidFValue) {
  Prng prng;
  BitSupplier rnd_func = Prng::Generate;
  void* rnd_param = &prng;
  JoinRequest join_request;
  GroupPubKey pub_key = kPubKey;
  FpElemStr f = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
  };
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };

  const BigNumStr p = {
      {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD, 0x46, 0xE5, 0xF2, 0x5E,
        0xEE, 0x71, 0xA4, 0x9E, 0x0C, 0xDC, 0x65, 0xFB, 0x12, 0x99, 0x92, 0x1A,
        0xF6, 0x2D, 0x53, 0x6C, 0xD1, 0x0B, 0x50, 0x0D}}};
  FiniteFieldObj Fp(p);
  FfElementObj el(&Fp);
  ASSERT_NE(kEpidNoErr, ReadFfElement(Fp, (uint8_t*)&f, sizeof(f), el));
  EXPECT_EQ(kEpidBadArgErr, EpidRequestJoin(&pub_key, &ni, &f, rnd_func,
                                            rnd_param, kSha256, &join_request));
}

TEST_F(EpidMemberTest,
       GeneratesValidJoinRequestGivenValidParametersUsingIKGFData) {
  Prng prng;
  BitSupplier rnd_func = Prng::Generate;
  void* rnd_param = &prng;
  JoinRequest join_request;
  FpElemStr f = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
  };
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  const GroupPubKey* grp_public_key = reinterpret_cast<const GroupPubKey*>(
      this->kGroupPublicKeyDataIkgf.data());
  EXPECT_EQ(kEpidNoErr, EpidRequestJoin(grp_public_key, &ni, &f, rnd_func,
                                        rnd_param, kSha256, &join_request));
}

TEST_F(EpidMemberTest, GeneratesValidJoinRequestGivenValidParameters) {
  Prng prng;
  BitSupplier rnd_func = Prng::Generate;
  void* rnd_param = &prng;
  JoinRequest join_request;
  GroupPubKey pub_key = kPubKey;
  FpElemStr f = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
  };
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  EXPECT_EQ(kEpidNoErr, EpidRequestJoin(&pub_key, &ni, &f, rnd_func, rnd_param,
                                        kSha256, &join_request));
}

TEST_F(EpidMemberTest, GeneratesDiffJoinRequestsOnMultipleCalls) {
  Prng prng;
  BitSupplier rnd_func = Prng::Generate;
  void* rnd_param = &prng;
  JoinRequest join_request1;
  JoinRequest join_request2;
  GroupPubKey pub_key = kPubKey;
  FpElemStr f = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
  };
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  prng.set_seed(0x1234);
  EXPECT_EQ(kEpidNoErr, EpidRequestJoin(&pub_key, &ni, &f, rnd_func, rnd_param,
                                        kSha256, &join_request1));
  EXPECT_EQ(kEpidNoErr, EpidRequestJoin(&pub_key, &ni, &f, rnd_func, rnd_param,
                                        kSha256, &join_request2));
  EXPECT_NE(0, memcmp(&join_request1, &join_request2, sizeof(join_request1)));
}

TEST_F(EpidMemberTest, GeneratesDiffJoinRequestsGivenDiffHashAlgs) {
  Prng prng;
  BitSupplier rnd_func = Prng::Generate;
  void* rnd_param = &prng;
  JoinRequest join_request1;
  JoinRequest join_request2;
  GroupPubKey pub_key = kPubKey;
  FpElemStr f = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
  };
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  prng.set_seed(0x1234);
  EXPECT_EQ(kEpidNoErr, EpidRequestJoin(&pub_key, &ni, &f, rnd_func, rnd_param,
                                        kSha256, &join_request1));
  prng.set_seed(0x1234);
  EXPECT_EQ(kEpidNoErr, EpidRequestJoin(&pub_key, &ni, &f, rnd_func, rnd_param,
                                        kSha512, &join_request2));
  EXPECT_NE(0, memcmp(&join_request1, &join_request2, sizeof(join_request1)));
}

TEST_F(EpidMemberTest, EpidAssemblePrivKeyFailsGivenNullParameters) {
  MembershipCredential credential = {this->kGrpXMember9PrivKey.gid,
                                     this->kGrpXMember9PrivKey.A,
                                     this->kGrpXMember9PrivKey.x};
  PrivKey new_priv_key;
  EXPECT_EQ(kEpidBadArgErr,
            EpidAssemblePrivKey(nullptr, &this->kGrpXMember9PrivKey.f,
                                &this->kGrpXKey, &new_priv_key));
  EXPECT_EQ(kEpidBadArgErr,
            EpidAssemblePrivKey(&credential, nullptr, &this->kGrpXKey,
                                &new_priv_key));
  EXPECT_EQ(kEpidBadArgErr,
            EpidAssemblePrivKey(&credential, &this->kGrpXMember9PrivKey.f,
                                nullptr, &new_priv_key));
  EXPECT_EQ(kEpidBadArgErr,
            EpidAssemblePrivKey(&credential, &this->kGrpXMember9PrivKey.f,
                                &this->kGrpXKey, nullptr));
}

TEST_F(EpidMemberTest, EpidAssemblePrivKeyFailsGivenGroupIdMissmatch) {
  // Check wrong gid for GroupPubKey
  PrivKey new_priv_key;
  MembershipCredential credential = {this->kGrpXMember9PrivKey.gid,
                                     this->kGrpXMember9PrivKey.A,
                                     this->kGrpXMember9PrivKey.x};
  FpElemStr f = this->kGrpXMember9PrivKey.f;
  GroupPubKey group_pub_key = this->kGrpXKey;
  group_pub_key.gid.data[0] = group_pub_key.gid.data[0] ^ 0xFF;
  EXPECT_EQ(kEpidBadArgErr, EpidAssemblePrivKey(&credential, &f, &group_pub_key,
                                                &new_priv_key));
  // Check wrong gid for PrivKey
  credential.gid.data[sizeof(credential.gid.data) - 1] =
      credential.gid.data[sizeof(credential.gid.data) - 1] ^ 0xFF;
  EXPECT_EQ(
      kEpidBadArgErr,
      EpidAssemblePrivKey(&credential, &f, &this->kGrpXKey, &new_priv_key));
  // Check wrong gid for both GroupPubKey and PrivKey
  EXPECT_EQ(kEpidBadArgErr, EpidAssemblePrivKey(&credential, &f, &group_pub_key,
                                                &new_priv_key));
}

TEST_F(EpidMemberTest, EpidAssemblePrivKeyRejectsInvalidPrivKey) {
  // test for invalid key components values (eg. out of range, not in EC group)
  PrivKey new_priv_key;
  MembershipCredential credential = {this->kGrpXMember9PrivKey.gid,
                                     this->kGrpXMember9PrivKey.A,
                                     this->kGrpXMember9PrivKey.x};
  FpElemStr f = this->kGrpXMember9PrivKey.f;
  credential.A.x.data.data[0] = 0xFF;
  EXPECT_EQ(
      kEpidBadArgErr,
      EpidAssemblePrivKey(&credential, &f, &this->kGrpXKey, &new_priv_key));
  credential.A = this->kGrpXMember9PrivKey.A;

  credential.A.y.data.data[0] = 0xFF;
  EXPECT_EQ(
      kEpidBadArgErr,
      EpidAssemblePrivKey(&credential, &f, &this->kGrpXKey, &new_priv_key));
  credential.A = this->kGrpXMember9PrivKey.A;

  FpElemStr inv_f = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
  };
  EXPECT_EQ(
      kEpidBadArgErr,
      EpidAssemblePrivKey(&credential, &inv_f, &this->kGrpXKey, &new_priv_key));

  credential.x.data.data[0] = 0xFF;
  EXPECT_EQ(
      kEpidBadArgErr,
      EpidAssemblePrivKey(&credential, &f, &this->kGrpXKey, &new_priv_key));
}

TEST_F(EpidMemberTest, EpidAssemblePrivKeyRejectsInvalidGroupKey) {
  // test for invalid key components values (eg. out of range, not in EC group)
  PrivKey new_priv_key;
  MembershipCredential credential = {this->kGrpXMember9PrivKey.gid,
                                     this->kGrpXMember9PrivKey.A,
                                     this->kGrpXMember9PrivKey.x};
  FpElemStr f = this->kGrpXMember9PrivKey.f;
  GroupPubKey pub_key = this->kGrpXKey;
  pub_key.h1.x.data.data[0] = 0xFF;
  EXPECT_EQ(kEpidBadArgErr,
            EpidAssemblePrivKey(&credential, &f, &pub_key, &new_priv_key));

  pub_key = this->kGrpXKey;
  pub_key.h1.y.data.data[0] = 0xFF;
  EXPECT_EQ(kEpidBadArgErr,
            EpidAssemblePrivKey(&credential, &f, &pub_key, &new_priv_key));

  pub_key = this->kGrpXKey;
  pub_key.h2.x.data.data[0] = 0xFF;
  EXPECT_EQ(kEpidBadArgErr,
            EpidAssemblePrivKey(&credential, &f, &pub_key, &new_priv_key));

  pub_key = this->kGrpXKey;
  pub_key.h2.y.data.data[0] = 0xFF;
  EXPECT_EQ(kEpidBadArgErr,
            EpidAssemblePrivKey(&credential, &f, &pub_key, &new_priv_key));

  pub_key = this->kGrpXKey;
  pub_key.w.x[0].data.data[0] = 0xFF;
  EXPECT_EQ(kEpidBadArgErr,
            EpidAssemblePrivKey(&credential, &f, &pub_key, &new_priv_key));

  pub_key = this->kGrpXKey;
  pub_key.w.x[1].data.data[0] = 0xFF;
  EXPECT_EQ(kEpidBadArgErr,
            EpidAssemblePrivKey(&credential, &f, &pub_key, &new_priv_key));

  pub_key = this->kGrpXKey;
  pub_key.w.y[0].data.data[0] = 0xFF;
  EXPECT_EQ(kEpidBadArgErr,
            EpidAssemblePrivKey(&credential, &f, &pub_key, &new_priv_key));

  pub_key = this->kGrpXKey;
  pub_key.w.y[1].data.data[0] = 0xFF;
  EXPECT_EQ(kEpidBadArgErr,
            EpidAssemblePrivKey(&credential, &f, &pub_key, &new_priv_key));
}

TEST_F(EpidMemberTest, EpidAssemblePrivKeyRejectsKeyNotInGroup) {
  PrivKey new_priv_key;
  MembershipCredential credential = {this->kGrpXMember9PrivKey.gid,
                                     this->kGrpXMember9PrivKey.A,
                                     this->kGrpXMember9PrivKey.x};
  FpElemStr f = this->kGrpXMember9PrivKey.f;
  EXPECT_EQ(
      kEpidBadArgErr,
      EpidAssemblePrivKey(&credential, &f, &this->kGrpYKey, &new_priv_key));
}

TEST_F(EpidMemberTest, EpidAssemblePrivKeyRejectsKeyNotInGroupUsingIKGFData) {
  const GroupPubKey* grp_public_key = reinterpret_cast<const GroupPubKey*>(
      this->kGroupPublicKeyDataIkgf.data());
  const PrivKey mbr_private_key = {
#include "epid/common-testhelper/testdata/ikgf/groupb/member0/mprivkey.inc"
  };
  PrivKey new_priv_key;
  MembershipCredential credential = {mbr_private_key.gid, mbr_private_key.A,
                                     mbr_private_key.x};
  FpElemStr f = mbr_private_key.f;
  EXPECT_EQ(kEpidBadArgErr, EpidAssemblePrivKey(&credential, &f, grp_public_key,
                                                &new_priv_key));
}

TEST_F(EpidMemberTest, EpidAssemblePrivKeyAssemblesKeyInGroup) {
  MembershipCredential credential = {this->kGrpXMember9PrivKey.gid,
                                     this->kGrpXMember9PrivKey.A,
                                     this->kGrpXMember9PrivKey.x};
  PrivKey new_priv_key;
  EXPECT_EQ(kEpidNoErr,
            EpidAssemblePrivKey(&credential, &this->kGrpXMember9PrivKey.f,
                                &this->kGrpXKey, &new_priv_key));
  EXPECT_EQ(0, memcmp(&this->kGrpXMember9PrivKey, &new_priv_key,
                      sizeof(new_priv_key)));
}

}  // namespace
