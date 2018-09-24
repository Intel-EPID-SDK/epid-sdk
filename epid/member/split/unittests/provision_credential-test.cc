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

/*!
 * \file
 * \brief Provision Credential unit tests.
 */
#include <cstring>
#include <vector>

#include "gtest/gtest.h"

extern "C" {
#include "epid/member/api.h"
#include "epid/member/split/src/context.h"
#include "epid/member/split/src/storage.h"
}

#include "epid/common-testhelper/epid_gtest-testhelper.h"
#include "epid/common-testhelper/errors-testhelper.h"
#include "epid/common-testhelper/mem_params-testhelper.h"
#include "epid/common-testhelper/prng-testhelper.h"
#include "epid/common-testhelper/verifier_wrapper-testhelper.h"
#include "epid/member/split/unittests/member-testhelper.h"

namespace {
void set_gid_hashalg(GroupId* id, HashAlg hashalg) {
  id->data[1] = (id->data[1] & 0xf0) | (hashalg & 0x0f);
}

const FpElemStr f = {0x48, 0x40, 0xb5, 0x6c, 0x6d, 0x47, 0x09, 0x0b,
                     0x05, 0xd6, 0x43, 0x56, 0xe0, 0x7c, 0xc6, 0x8e,
                     0xa1, 0x65, 0x67, 0xfd, 0xa7, 0x07, 0x87, 0x9b,
                     0x36, 0x2d, 0x41, 0x35, 0x63, 0x61, 0x31, 0xc7};

const MembershipCredential kGrpXMember3Sha512Credential = {
#include "epid/common-testhelper/testdata/split/grp_x/member3/membercredential_grpx_member3_sha512_01.inc"
};

const MemberPrecomp kGrpXMember3Sha512Precomp = {
#include "epid/common-testhelper/testdata/split/grp_x/member3/precomp_grpx_member3_sha512_01.inc"
};

const PrivKey kGrpXMember3Sha256PrivKey = {
#include "epid/common-testhelper/testdata/grp_x/member3/mprivkey_sha256_01.inc"
};

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

TEST_F(EpidSplitMemberTest, ProvisionCredentialFailsGivenNullParameters) {
  Prng prng;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionCredential(nullptr, &this->kGrpXKey,
                                    &kGrpXMember3Sha512Credential,
                                    &kGrpXMember3Sha512Precomp));
  EXPECT_EQ(kEpidBadArgErr, EpidProvisionCredential(
                                member, nullptr, &kGrpXMember3Sha512Credential,
                                &kGrpXMember3Sha512Precomp));
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionCredential(member, &this->kGrpXKey, nullptr,
                                    &kGrpXMember3Sha512Precomp));
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionCredential(nullptr, &this->kGrpXKey,
                                    &kGrpXMember3Sha512Credential, nullptr));
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionCredential(member, nullptr,
                                    &kGrpXMember3Sha512Credential, nullptr));
  EXPECT_EQ(kEpidBadArgErr,
            EpidProvisionCredential(member, &this->kGrpXKey, nullptr, nullptr));
}

TEST_F(EpidSplitMemberTest, ProvisionCredentialRejectsInvalidCredential) {
  Prng prng;
  MembershipCredential wrong_credential;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);

  wrong_credential = kGrpXMember3Sha512Credential;
  wrong_credential.A.x.data.data[0]++;
  EXPECT_EQ(
      kEpidKeyNotInGroupErr,
      ProvisionCredentialAndStart(member, &this->kGrpXKey, &wrong_credential,
                                  &kGrpXMember3Sha512Precomp));
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(member, &this->kGrpXKey,
                                        &wrong_credential, nullptr));

  wrong_credential = kGrpXMember3Sha512Credential;
  wrong_credential.A.y.data.data[0]++;
  EXPECT_EQ(
      kEpidKeyNotInGroupErr,
      ProvisionCredentialAndStart(member, &this->kGrpXKey, &wrong_credential,
                                  &kGrpXMember3Sha512Precomp));
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(member, &this->kGrpXKey,
                                        &wrong_credential, nullptr));

  wrong_credential = kGrpXMember3Sha512Credential;
  wrong_credential.x.data.data[0]++;
  EXPECT_EQ(
      kEpidKeyNotInGroupErr,
      ProvisionCredentialAndStart(member, &this->kGrpXKey, &wrong_credential,
                                  &kGrpXMember3Sha512Precomp));
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(member, &this->kGrpXKey,
                                        &wrong_credential, nullptr));
}

TEST_F(EpidSplitMemberTest, ProvisionCredentialRejectsInvalidGroupKey) {
  Prng prng;
  GroupPubKey pub_key = this->kGrpXKey;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);

  pub_key = this->kGrpXKey;
  pub_key.h1.x.data.data[0]++;
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(member, &pub_key,
                                        &kGrpXMember3Sha512Credential,
                                        &kGrpXMember3Sha512Precomp));
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(
                member, &pub_key, &kGrpXMember3Sha512Credential, nullptr));

  pub_key = this->kGrpXKey;
  pub_key.h1.y.data.data[0]++;
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(member, &pub_key,
                                        &kGrpXMember3Sha512Credential,
                                        &kGrpXMember3Sha512Precomp));
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(
                member, &pub_key, &kGrpXMember3Sha512Credential, nullptr));

  pub_key = this->kGrpXKey;
  pub_key.h2.x.data.data[0]++;
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(member, &pub_key,
                                        &kGrpXMember3Sha512Credential,
                                        &kGrpXMember3Sha512Precomp));
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(
                member, &pub_key, &kGrpXMember3Sha512Credential, nullptr));

  pub_key = this->kGrpXKey;
  pub_key.h2.y.data.data[0]++;
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(member, &pub_key,
                                        &kGrpXMember3Sha512Credential,
                                        &kGrpXMember3Sha512Precomp));
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(
                member, &pub_key, &kGrpXMember3Sha512Credential, nullptr));

  pub_key = this->kGrpXKey;
  pub_key.w.x[0].data.data[0]++;
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(member, &pub_key,
                                        &kGrpXMember3Sha512Credential,
                                        &kGrpXMember3Sha512Precomp));
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(
                member, &pub_key, &kGrpXMember3Sha512Credential, nullptr));

  pub_key = this->kGrpXKey;
  pub_key.w.x[1].data.data[0]++;
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(member, &pub_key,
                                        &kGrpXMember3Sha512Credential,
                                        &kGrpXMember3Sha512Precomp));
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(
                member, &pub_key, &kGrpXMember3Sha512Credential, nullptr));

  pub_key = this->kGrpXKey;
  pub_key.w.y[0].data.data[0]++;
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(member, &pub_key,
                                        &kGrpXMember3Sha512Credential,
                                        &kGrpXMember3Sha512Precomp));
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(
                member, &pub_key, &kGrpXMember3Sha512Credential, nullptr));

  pub_key = this->kGrpXKey;
  pub_key.w.y[1].data.data[0]++;
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(member, &pub_key,
                                        &kGrpXMember3Sha512Credential,
                                        &kGrpXMember3Sha512Precomp));
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(
                member, &pub_key, &kGrpXMember3Sha512Credential, nullptr));
}

TEST_F(EpidSplitMemberTest, ProvisionCredentialRejectsCredentialNotInGroup) {
  Prng prng;
  MembershipCredential wrong_credential;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);

  wrong_credential = kGrpXMember3Sha512Credential;
  wrong_credential.gid.data[0] = ~wrong_credential.gid.data[0];
  EXPECT_EQ(
      kEpidKeyNotInGroupErr,
      ProvisionCredentialAndStart(member, &this->kGrpXKey, &wrong_credential,
                                  &kGrpXMember3Sha512Precomp));
  EXPECT_EQ(kEpidKeyNotInGroupErr,
            ProvisionCredentialAndStart(member, &this->kGrpXKey,
                                        &wrong_credential, nullptr));
}

TEST_F(EpidSplitMemberTest, CanProvisionUsingMembershipCredentialPrecomp) {
  Prng prng;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  GroupPubKey pub_key = this->kGrpXKey;
  MembershipCredential cred = kGrpXMember3Sha512Credential;
  set_gid_hashalg(&pub_key.gid, kSha512);
  set_gid_hashalg(&cred.gid, kSha512);
  EXPECT_EQ(kEpidNoErr,
            ProvisionCredentialAndStart(member, &pub_key, &cred,
                                        &kGrpXMember3Sha512Precomp));
}

TEST_F(EpidSplitMemberTest, CanProvisionUsingMembershipCredentialNoPrecomp) {
  Prng prng;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  GroupPubKey pub_key = this->kGrpXKey;
  MembershipCredential cred = kGrpXMember3Sha512Credential;
  set_gid_hashalg(&pub_key.gid, kSha512);
  set_gid_hashalg(&cred.gid, kSha512);
  EXPECT_EQ(kEpidNoErr,
            ProvisionCredentialAndStart(member, &pub_key, &cred, nullptr));
}

TEST_F(EpidSplitMemberTest,
       ProvisionCredentialCanStoreMembershipCredentialNoPrecomp) {
  Prng prng;
  GroupPubKey pubkey = this->kGrpXKey;
  MembershipCredential cred = kGrpXMember3Sha512Credential;
  MembershipCredential expected_cred = kGrpXMember3Sha512Credential;
  set_gid_hashalg(&pubkey.gid, kSha512);
  set_gid_hashalg(&cred.gid, kSha512);
  set_gid_hashalg(&expected_cred.gid, kSha512);

  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoErr,
            ProvisionCredentialAndStart(member, &pubkey, &cred, nullptr));

  MembershipCredential saved_credential;
  EXPECT_EQ(kEpidNoErr,
            EpidNvReadMembershipCredential(((MemberCtx*)member)->tpm2_ctx,
                                           &pubkey, &saved_credential));
  EXPECT_EQ(saved_credential, expected_cred);
}

void SetHashBitsInGid(unsigned int code, GroupPubKey* pub_key,
                      MembershipCredential* credential) {
  pub_key->gid.data[1] &= 0xf0;
  pub_key->gid.data[1] |= (code & 0x0f);
  credential->gid.data[1] &= 0xf0;
  credential->gid.data[1] |= (code & 0x0f);
}

TEST_F(EpidSplitMemberTest,
       ProvisionCredentialFailsGivenGroupWithUnsupportedHashAlg) {
  Prng prng;
  GroupPubKey pub_key = this->kGrpXKey;
  MembershipCredential credential = kGrpXMember3Sha512Credential;
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

TEST_F(EpidSplitMemberTest, ProvisionCredentialUsesCorrectPrimary) {
  Prng prng;
  GroupPubKey pub_key = this->kGrpXKey;
  PrivKey mpriv_key = kGrpXMember3Sha256PrivKey;
  MembershipCredential cred = kGrpXMember3Sha512Credential;
  MemberParams params = {0};

  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);

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
  set_gid_hashalg(&pub_key.gid, kSha512);
  set_gid_hashalg(&cred.gid, kSha512);
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
