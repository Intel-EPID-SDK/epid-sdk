/*############################################################################
  # Copyright 2017-2020 Intel Corporation
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
 * \brief Provision key unit tests.
 */
#include <cstring>
#include <vector>

#include "gtest/gtest.h"
#include "testhelper/epid_gtest-testhelper.h"

#include "member-testhelper.h"
#include "testhelper/errors-testhelper.h"
#include "testhelper/mem_params-testhelper.h"
#include "testhelper/prng-testhelper.h"
#include "testhelper/verifier_wrapper-testhelper.h"

extern "C" {
#include "epid/member/api.h"
}

namespace {
EpidStatus ProvisionBulkAndStart(MemberCtx* ctx, GroupPubKey const* pub_key,
                                 PrivKey const* priv_key,
                                 MemberPrecomp const* precomp_str) {
  EpidStatus sts;
  sts = EpidProvisionKey(ctx, pub_key, priv_key, precomp_str);
  if (sts != kEpidNoErr) {
    return sts;
  }
  sts = EpidMemberStartup(ctx);
  return sts;
}

TEST_F(EpidMemberTest, ProvisionBulkFailsGivenNullParameters) {
  Prng prng;
  GroupPubKey pub_key = this->kGroupPublicKey;
  PrivKey priv_key = this->kMemberPrivateKey;
  MemberPrecomp precomp = this->kMemberPrecomp;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, nullptr, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionKey(nullptr, &pub_key, &priv_key, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionKey(member, nullptr, &priv_key, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionKey(member, &pub_key, nullptr, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionKey(nullptr, &pub_key, &priv_key, nullptr));
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionKey(member, nullptr, &priv_key, nullptr));
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionKey(member, &pub_key, nullptr, nullptr));
}

TEST_F(EpidMemberTest, ProvisionBulkSucceedsGivenValidParameters) {
  Prng prng;
  GroupPubKey pub_key = this->kGroupPublicKey;
  PrivKey priv_key = this->kMemberPrivateKey;
  MemberPrecomp precomp = this->kMemberPrecomp;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, nullptr, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoErr,
            EpidProvisionKey(member, &pub_key, &priv_key, &precomp));
  EXPECT_EQ(kEpidNoErr, EpidProvisionKey(member, &pub_key, &priv_key, nullptr));
}

// test that create succeeds with valid IKGF given parameters
TEST_F(EpidMemberTest, ProvisionBulkSucceedsGivenValidParametersUsingIKGFData) {
  Prng prng;
  const GroupPubKey pub_key = {
#include "testhelper/testdata/ikgf/groupa/pubkey.inc"
  };
  const PrivKey priv_key = {
#include "testhelper/testdata/ikgf/groupa/member0/mprivkey.inc"
  };

  const MemberPrecomp precomp = {
#include "testhelper/testdata/ikgf/groupa/member0/mprecomp.inc"
  };
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, nullptr, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoErr,
            EpidProvisionKey(member, &pub_key, &priv_key, &precomp));
  EXPECT_EQ(kEpidNoErr, EpidProvisionKey(member, &pub_key, &priv_key, nullptr));
}

TEST_F(EpidMemberTest, ProvisionBulkFailsForInvalidGroupPubKey) {
  Prng prng;

  GroupPubKey pub_key = this->kGroupPublicKey;
  PrivKey priv_key = this->kMemberPrivateKey;
  MemberPrecomp precomp = this->kMemberPrecomp;
  MemberParams params = {0};

  SetMemberParams(&Prng::Generate, &prng, nullptr, &params);
  MemberCtxObj member(&params);

  pub_key = this->kGroupPublicKey;
  pub_key.h1.x.data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, nullptr));

  pub_key = this->kGroupPublicKey;
  pub_key.h1.y.data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, nullptr));

  pub_key = this->kGroupPublicKey;
  pub_key.h2.x.data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, nullptr));

  pub_key = this->kGroupPublicKey;
  pub_key.h2.y.data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, nullptr));

  pub_key = this->kGroupPublicKey;
  pub_key.w.x[0].data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, nullptr));

  pub_key = this->kGroupPublicKey;
  pub_key.w.x[1].data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, nullptr));

  pub_key = this->kGroupPublicKey;
  pub_key.w.y[0].data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, nullptr));

  pub_key = this->kGroupPublicKey;
  pub_key.w.y[1].data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, nullptr));
}

TEST_F(EpidMemberTest, ProvisionBulkFailsForInvalidF) {
  Prng prng;
  FpElemStr f = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
  };
  GroupPubKey pub_key = this->kGroupPublicKey;
  PrivKey priv_key = this->kMemberPrivateKey;
  MemberPrecomp precomp = this->kMemberPrecomp;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, nullptr, &params);
  MemberCtxObj member(&params);

  priv_key = this->kMemberPrivateKey;
  priv_key.f = f;
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, nullptr));
}

TEST_F(EpidMemberTest, ProvisionBulkFailsForInvalidPrivateKey) {
  Prng prng;

  GroupPubKey pub_key = this->kGroupPublicKey;
  PrivKey priv_key = this->kMemberPrivateKey;
  MemberPrecomp precomp = this->kMemberPrecomp;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, nullptr, &params);
  MemberCtxObj member(&params);

  priv_key = this->kMemberPrivateKey;
  priv_key.A.x.data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, nullptr));

  priv_key = this->kMemberPrivateKey;
  priv_key.A.y.data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            ProvisionBulkAndStart(member, &pub_key, &priv_key, nullptr));
}

void SetHashBitsInGid(unsigned int code, GroupPubKey* pub_key,
                      PrivKey* priv_key) {
  pub_key->gid.data[1] &= 0xf0;
  pub_key->gid.data[1] |= (code & 0x0f);
  priv_key->gid.data[1] &= 0xf0;
  priv_key->gid.data[1] |= (code & 0x0f);
}

TEST_F(EpidMemberTest, ProvisionBulkFailsGivenGroupWithUnsupportedHashAlg) {
  Prng prng;
  GroupPubKey pub_key = this->kGroupPublicKey;
  PrivKey priv_key = this->kMemberPrivateKey;
  MemberPrecomp precomp = this->kMemberPrecomp;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, nullptr, &params);
  MemberCtxObj member(&params);
  for (unsigned int invalid_hash = 0x4; invalid_hash <= 0xf; invalid_hash++) {
    SetHashBitsInGid(invalid_hash, &pub_key, &priv_key);
    EXPECT_EQ(kEpidHashAlgorithmNotSupported,
              EpidProvisionKey(member, &pub_key, &priv_key, &precomp))
        << "Unsupported hash algorithm (" << std::showbase << std::hex
        << invalid_hash << ") is actually supported";
  }
}

TEST_F(EpidMemberTest, CanProvisionAfterCreatingJoinRequestForDifferentGroup) {
  Prng my_prng;
  // create member with specific f
  GroupPubKey pub_key = this->kGroupPublicKey;
  PrivKey mpriv_key = this->kMemberPrivateKey;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &my_prng, &mpriv_key.f, &params);
  MemberCtxObj member(&params);
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());

  // create join request into one group
  pub_key.gid.data[1] &= 0xf0;
  pub_key.gid.data[1] |= 0x01;  // sha384
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));

  // provision into another group
  EXPECT_EQ(kEpidNoErr, EpidProvisionKey(member, &this->kGroupPublicKey,
                                         &mpriv_key, &this->kMemberPrecomp));
  // startup
  EXPECT_EQ(kEpidNoErr, EpidMemberStartup(member));

  auto& msg = this->kMsg0;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSignature* sig = reinterpret_cast<EpidSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);

  // sign message
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));

  // verify signature
  VerifierCtxObj ctx(this->kGroupPublicKey);
  EXPECT_EQ(kEpidSigValid,
            EpidVerify(ctx, sig, sig_len, msg.data(), msg.size()));
}
}  // namespace
