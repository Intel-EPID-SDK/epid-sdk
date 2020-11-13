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
 * \brief Provision credential unit tests.
 */
#include <cstring>
#include <vector>

#include "gtest/gtest.h"

extern "C" {
#include "epid/member/api.h"
}

#include "member-testhelper.h"
#include "testhelper/epid_gtest-testhelper.h"
#include "testhelper/errors-testhelper.h"
#include "testhelper/mem_params-testhelper.h"
#include "testhelper/prng-testhelper.h"
#include "testhelper/verifier_wrapper-testhelper.h"

namespace {
EpidStatus ProvisionCredentialAndStart(MemberCtx* ctx,
                                       GroupPubKey const* pub_key,
                                       MembershipCredential const* credential,
                                       MemberPrecomp const* precomp_str) {
  EpidStatus sts;
  sts = EpidProvisionCredential(ctx, pub_key, credential, precomp_str);
  if (sts != kEpidNoErr) {
    return sts;
  }
  sts = EpidMemberStartup(ctx);
  return sts;
}

TEST_F(EpidMemberTest, ProvisionCredentialFailsGivenNullParameters) {
  Prng prng;
  GroupPubKey pub_key = this->kGrpXKey;
  FpElemStr f = this->kGrpXMember9PrivKey.f;
  MembershipCredential credential;
  credential.A = this->kGrpXMember9PrivKey.A;
  credential.gid = this->kGrpXMember9PrivKey.gid;
  credential.x = this->kGrpXMember9PrivKey.x;
  // Note: this MemberPrecomp is for the wrong group, however it should not
  // be checked in Provision because doing so would negate the performance
  // boost of using the precomp.
  MemberPrecomp precomp = this->kMemberPrecomp;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionCredential(nullptr, &pub_key, &credential, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionCredential(member, nullptr, &credential, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionCredential(member, &pub_key, nullptr, &precomp));
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionCredential(nullptr, &pub_key, &credential, nullptr));
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionCredential(member, nullptr, &credential, nullptr));
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionCredential(member, &pub_key, nullptr, nullptr));
}

TEST_F(EpidMemberTest, ProvisionCredentialRejectsInvalidCredential) {
  Prng prng;
  GroupPubKey pub_key = this->kGrpXKey;
  FpElemStr f = this->kGrpXMember9PrivKey.f;
  MembershipCredential credential;
  MembershipCredential base_credential;
  base_credential.A = this->kGrpXMember9PrivKey.A;
  base_credential.gid = this->kGrpXMember9PrivKey.gid;
  base_credential.x = this->kGrpXMember9PrivKey.x;
  // Note: this MemberPrecomp is for the wrong group, however it should not
  // be checked in Provision because doing so would negate the performance
  // boost of using the precomp.
  MemberPrecomp precomp = this->kMemberPrecomp;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);

  credential = base_credential;
  credential.A.x.data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, &precomp));
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, nullptr));

  credential = base_credential;
  credential.A.y.data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, &precomp));
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, nullptr));

  credential = base_credential;
  credential.x.data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, &precomp));
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, nullptr));
}

TEST_F(EpidMemberTest, ProvisionCredentialRejectsInvalidGroupKey) {
  Prng prng;
  GroupPubKey pub_key = this->kGrpXKey;
  FpElemStr f = this->kGrpXMember9PrivKey.f;
  MembershipCredential credential;
  credential.A = this->kGrpXMember9PrivKey.A;
  credential.gid = this->kGrpXMember9PrivKey.gid;
  credential.x = this->kGrpXMember9PrivKey.x;
  // Note: this MemberPrecomp is for the wrong group, however it should not
  // be checked in Provision because doing so would negate the performance
  // boost of using the precomp.
  MemberPrecomp precomp = this->kMemberPrecomp;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);

  pub_key = this->kGroupPublicKey;
  pub_key.h1.x.data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, &precomp));
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, nullptr));

  pub_key = this->kGroupPublicKey;
  pub_key.h1.y.data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, &precomp));
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, nullptr));

  pub_key = this->kGroupPublicKey;
  pub_key.h2.x.data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, &precomp));
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, nullptr));

  pub_key = this->kGroupPublicKey;
  pub_key.h2.y.data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, &precomp));
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, nullptr));

  pub_key = this->kGroupPublicKey;
  pub_key.w.x[0].data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, &precomp));
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, nullptr));

  pub_key = this->kGroupPublicKey;
  pub_key.w.x[1].data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, &precomp));
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, nullptr));

  pub_key = this->kGroupPublicKey;
  pub_key.w.y[0].data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, &precomp));
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, nullptr));

  pub_key = this->kGroupPublicKey;
  pub_key.w.y[1].data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, &precomp));
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, nullptr));
}

TEST_F(EpidMemberTest, ProvisionCredentialRejectsCredentialNotInGroup) {
  Prng prng;
  GroupPubKey pub_key = this->kGrpXKey;
  FpElemStr f = this->kGrpXMember9PrivKey.f;
  MembershipCredential credential;
  MembershipCredential base_credential;
  base_credential.A = this->kGrpXMember9PrivKey.A;
  base_credential.gid = this->kGrpXMember9PrivKey.gid;
  base_credential.x = this->kGrpXMember9PrivKey.x;
  // Note: this MemberPrecomp is for the wrong group, however it should not
  // be checked in Provision because doing so would negate the performance
  // boost of using the precomp.
  MemberPrecomp precomp = this->kMemberPrecomp;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);

  credential = base_credential;
  credential.gid.data[0] = ~credential.gid.data[0];
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, &precomp));
  EXPECT_EQ(kEpidBadArgErr, ProvisionCredentialAndStart(member, &pub_key,
                                                        &credential, nullptr));
}

TEST_F(EpidMemberTest, CanProvisionUsingMembershipCredentialPrecomp) {
  Prng prng;
  GroupPubKey pub_key = this->kGrpXKey;
  FpElemStr f = this->kGrpXMember9PrivKey.f;
  MembershipCredential credential;
  credential.A = this->kGrpXMember9PrivKey.A;
  credential.gid = this->kGrpXMember9PrivKey.gid;
  credential.x = this->kGrpXMember9PrivKey.x;
  // Note: this MemberPrecomp is for the wrong group, however it should not
  // be checked in Provision because doing so would negate the performance
  // boost of using the precomp.
  MemberPrecomp precomp = this->kMemberPrecomp;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoErr, ProvisionCredentialAndStart(member, &pub_key,
                                                    &credential, &precomp));
}

TEST_F(EpidMemberTest, CanProvisionUsingMembershipCredentialNoPrecomp) {
  Prng prng;
  GroupPubKey pub_key = this->kGrpXKey;
  FpElemStr f = this->kGrpXMember9PrivKey.f;
  MembershipCredential credential;
  credential.A = this->kGrpXMember9PrivKey.A;
  credential.gid = this->kGrpXMember9PrivKey.gid;
  credential.x = this->kGrpXMember9PrivKey.x;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoErr, ProvisionCredentialAndStart(member, &pub_key,
                                                    &credential, nullptr));
}

// test that create succeeds with valid IKGF given parameters
TEST_F(EpidMemberTest, CanProvisionUsingIKGFMembershipCredentialPrecomp) {
  Prng prng;
  const GroupPubKey* pub_key = reinterpret_cast<const GroupPubKey*>(
      this->kGroupPublicKeyDataIkgf.data());
  const PrivKey* priv_key =
      reinterpret_cast<const PrivKey*>(this->kMemberPrivateKeyDataIkgf.data());
  FpElemStr f = priv_key->f;
  MembershipCredential credential;
  credential.A = priv_key->A;
  credential.gid = priv_key->gid;
  credential.x = priv_key->x;
  // Note: this MemberPrecomp is for the wrong group, however it should not
  // be checked in Provision because doing so would negate the performance
  // boost of using the precomp.
  MemberPrecomp precomp = this->kMemberPrecomp;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoErr, ProvisionCredentialAndStart(member, pub_key,
                                                    &credential, &precomp));
}

TEST_F(EpidMemberTest, CanProvisionUsingIKGFMembershipCredentialNoPrecomp) {
  Prng prng;
  const GroupPubKey* pub_key = reinterpret_cast<const GroupPubKey*>(
      this->kGroupPublicKeyDataIkgf.data());
  const PrivKey* priv_key =
      reinterpret_cast<const PrivKey*>(this->kMemberPrivateKeyDataIkgf.data());
  FpElemStr f = priv_key->f;
  MembershipCredential credential;
  credential.A = priv_key->A;
  credential.gid = priv_key->gid;
  credential.x = priv_key->x;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoErr,
            ProvisionCredentialAndStart(member, pub_key, &credential, nullptr));
}

void SetHashBitsInGid(unsigned int code, GroupPubKey* pub_key,
                      MembershipCredential* credential) {
  pub_key->gid.data[1] &= 0xf0;
  pub_key->gid.data[1] |= (code & 0x0f);
  credential->gid.data[1] &= 0xf0;
  credential->gid.data[1] |= (code & 0x0f);
}

TEST_F(EpidMemberTest,
       ProvisionCredentialFailsGivenGroupWithUnsupportedHashAlg) {
  Prng prng;
  GroupPubKey pub_key = this->kGrpXKey;
  FpElemStr f = this->kGrpXMember9PrivKey.f;
  MembershipCredential credential;
  credential.A = this->kGrpXMember9PrivKey.A;
  credential.gid = this->kGrpXMember9PrivKey.gid;
  credential.x = this->kGrpXMember9PrivKey.x;
  // Note: this MemberPrecomp is for the wrong group, however it should not
  // be checked in Provision because doing so would negate the performance
  // boost of using the precomp.
  MemberPrecomp precomp = this->kMemberPrecomp;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);

  for (unsigned int invalid_hash = 0x4; invalid_hash <= 0xf; invalid_hash++) {
    SetHashBitsInGid(invalid_hash, &pub_key, &credential);
    EXPECT_EQ(kEpidHashAlgorithmNotSupported,
              EpidProvisionCredential(member, &pub_key, &credential, &precomp))
        << "Unsupported hash algorithm (" << std::showbase << std::hex
        << invalid_hash << ") is actually supported";
  }
}

TEST_F(EpidMemberTest, ProvisionCredentialUsesCorrectPrimary) {
  Prng prng;
  GroupPubKey pub_key = this->kGroupPublicKey;
  PrivKey mpriv_key = this->kMemberPrivateKey;
  MembershipCredential cred = {0};
  MemberParams params = {0};

  SetMemberParams(&Prng::Generate, &prng, &mpriv_key.f, &params);
  MemberCtxObj member(&params);
  cred.gid = mpriv_key.gid;
  cred.A = mpriv_key.A;
  cred.x = mpriv_key.x;

  EXPECT_EQ(kEpidNoErr,
            EpidProvisionKey(member, &pub_key, &mpriv_key, nullptr));
  EXPECT_EQ(kEpidNoErr, EpidMemberStartup(member));
  auto& msg = this->kMsg0;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSignature* sig = reinterpret_cast<EpidSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  // sign message
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  // verify signature
  VerifierCtxObj ctx(pub_key);
  EXPECT_EQ(kEpidSigValid,
            EpidVerify(ctx, sig, sig_len, msg.data(), msg.size()));

  // set sha512
  pub_key.gid.data[1] = 0x02;
  cred.gid.data[1] = 0x02;
  // re-provision member
  EXPECT_EQ(kEpidNoErr,
            EpidProvisionCredential(member, &pub_key, &cred, nullptr));
  EXPECT_EQ(kEpidNoErr, EpidMemberStartup(member));
  // sign message
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  // verify signature
  EXPECT_EQ(kEpidNoErr, EpidVerifierSetHashAlg(ctx, kSha512));
  EXPECT_EQ(kEpidSigValid,
            EpidVerify(ctx, sig, sig_len, msg.data(), msg.size()));
}
}  // namespace
