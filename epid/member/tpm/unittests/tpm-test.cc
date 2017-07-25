/*############################################################################
  # Copyright 2017 Intel Corporation
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
/// Tpm unit tests.
/*!
 * \file
 */
#include <cstring>

#include "gtest/gtest.h"

#include "epid/member/tpm/unittests/tpm-testhelper.h"
#include "epid/common-testhelper/prng-testhelper.h"
#include "epid/common-testhelper/errors-testhelper.h"
#include "epid/common-testhelper/verifier_wrapper-testhelper.h"

extern "C" {
#include "epid/member/tpm/context.h"
#include "epid/member/tpm/init.h"
#include "epid/member/tpm/validatekey.h"
#include "epid/member/tpm/sign.h"
#include "epid/common/types.h"
#include "epid/member/tpm/join.h"
#include "epid/member/tpm/nrprove.h"

#include "epid/member/src/sign_commitment.h"
#include "epid/member/src/hash_basename.h"
#include "epid/member/src/nrprove_commitment.h"
#include "epid/member/src/precomp.h"

#include "epid/verifier/api.h"
}

#if !defined(ntohl)
/// Macro to transform oct str 32 into uint_32
#define ntohl(u32)                                    \
  ((uint32_t)(((((unsigned char*)&(u32))[0]) << 24) + \
              ((((unsigned char*)&(u32))[1]) << 16) + \
              ((((unsigned char*)&(u32))[2]) << 8) +  \
              (((unsigned char*)&(u32))[3])))
#endif

namespace {
//////////////////////////////////////////////////////////////////////////
// Test showing how to do host signing

// SignsMessageUsingBasenameWithSigRl
TEST_F(EpidTpmTest, SignsMessageUsingBasenameWithSigRl) {
  // create TPM
  Prng my_prng;
  Epid2ParamsObj epid2params;
  TpmCtxObj tpm(&Prng::Generate, &my_prng, epid2params);

  // provision TPM
  const GroupPubKey pub_key = this->kGroupPublicKey;
  const PrivKey priv_key = this->kMemberPrivateKey;
  MemberPrecomp precomp = {0};
  EXPECT_EQ(kEpidNoErr, PrecomputeMemberPairing(epid2params, &pub_key,
                                                &priv_key.A, &precomp));

  EXPECT_EQ(kEpidNoErr, TpmProvision(tpm, &priv_key.f));
  // optional validity check. May not be needed if validity is ensured
  // by other means
  EXPECT_TRUE(
      TpmIsKeyValid(tpm, &priv_key.A, &priv_key.x, &pub_key.h1, &pub_key.w));
  EXPECT_EQ(kEpidNoErr, TpmInit(tpm, &priv_key.A, &priv_key.x, &pub_key.h1,
                                &pub_key.h2, &pub_key.w, &precomp));

  HashAlg hash_alg = kSha512;
  auto& bsn = this->kBsn0;

  // In actual implementation check the basename is allowed before
  // hashing

  G1ElemStr B = {0};
  EXPECT_EQ(kEpidNoErr, HashBaseName(epid2params.G1(), hash_alg, bsn.data(),
                                     bsn.size(), &B));

  // Begin Basic signing
  SignCommitOutput commit_out = {0};
  EXPECT_EQ(kEpidNoErr, TpmSignCommit(tpm, &B, &commit_out));

  std::vector<uint8_t> sig_data(sizeof(EpidSignature) - sizeof(NrProof));
  EpidSignature* sig = reinterpret_cast<EpidSignature*>(sig_data.data());
  sig->sigma0.B = commit_out.B;
  sig->sigma0.K = commit_out.K;
  sig->sigma0.T = commit_out.T;

  auto& msg = this->kMsg0;
  EXPECT_EQ(kEpidNoErr, HashSignCommitment(epid2params.Fp(), hash_alg, &pub_key,
                                           &commit_out, msg.data(), msg.size(),
                                           &sig->sigma0.c));

  EXPECT_EQ(kEpidNoErr,
            TpmSign(tpm, &sig->sigma0.c, &sig->sigma0.sx, &sig->sigma0.sf,
                    &sig->sigma0.sa, &sig->sigma0.sb));

  // Compute non-revoked proofs
  SigRl const* sigrl =
      reinterpret_cast<SigRl const*>(this->kSigRl5EntryData.data());
  const size_t sigrl_len = this->kSigRl5EntryData.size();

  const uint32_t n2 = ntohl(sigrl->n2);
  sig_data.resize(sig_data.size() + n2 * sizeof(NrProof));
  sig = reinterpret_cast<EpidSignature*>(sig_data.data());  // after resize!
  sig->rl_ver = sigrl->version;
  sig->n2 = sigrl->n2;

  for (uint32_t i = 0; i < n2; i++) {
    NrProveCommitOutput nrp_commit_out = {0};
    EXPECT_EQ(kEpidNoErr, TpmNrProveCommit(tpm, &sig->sigma0.B, &sig->sigma0.K,
                                           &sigrl->bk[i], &nrp_commit_out));
    NrProof* nr_proof = &sig->sigma[i];
    nr_proof->T = nrp_commit_out.T;
    EXPECT_EQ(kEpidNoErr, HashNrProveCommitment(
                              epid2params.Fp(), hash_alg, &sig->sigma0.B,
                              &sig->sigma0.K, &sigrl->bk[i], &nrp_commit_out,
                              msg.data(), msg.size(), &nr_proof->c));
    EXPECT_EQ(kEpidNoErr,
              TpmNrProve(tpm, &nr_proof->c, &nr_proof->smu, &nr_proof->snu));
  }

  // verify
  VerifierCtxObj ctx(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(ctx, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetSigRl(ctx, sigrl, sigrl_len));
  EXPECT_EQ(kEpidSigValid,
            EpidVerify(ctx, sig, sig_data.size(), msg.data(), msg.size()));
}

//////////////////////////////////////////////////////////////////////////
// Split operation sequence Tests
TEST_F(EpidTpmTest, TpmSignFollowedByTpmSignDisallowed) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  TpmCtxObj tpm(&Prng::Generate, &my_prng, epid2params);
  // auto& msg = this->kMsg0;
  // auto& bsn = this->kBsn0;
  BasicSignature sigma0;
  THROW_ON_EPIDERR(TpmProvision(tpm, &this->kMemberPrivateKey.f));
  THROW_ON_EPIDERR(TpmInit(tpm, &this->kMemberPrivateKey.A,
                           &this->kMemberPrivateKey.x,
                           &this->kGroupPublicKey.h1, &this->kGroupPublicKey.h2,
                           &this->kGroupPublicKey.w, &this->kMemberPrecomp));
  SignCommitOutput commit_out = {0};

  THROW_ON_EPIDERR(TpmSignCommit(tpm, nullptr, &commit_out));

  EXPECT_EQ(kEpidNoErr, TpmSign(tpm, &sigma0.c, &sigma0.sx, &sigma0.sf,
                                &sigma0.sa, &sigma0.sb));
  EXPECT_EQ(
      kEpidOutOfSequenceError,
      TpmSign(tpm, &sigma0.c, &sigma0.sx, &sigma0.sf, &sigma0.sa, &sigma0.sb));

  EXPECT_EQ(kEpidNoErr, TpmSignCommit(tpm, nullptr, &commit_out));
}

TEST_F(EpidTpmTest, TpmJoinFollowedByTpmJoinDisallowed) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  TpmCtxObj tpm(&Prng::Generate, &my_prng, epid2params);
  THROW_ON_EPIDERR(TpmProvision(tpm, &this->kMemberPrivateKey.f));

  JoinRequest join_request;
  G1ElemStr R_str = {0};
  THROW_ON_EPIDERR(TpmJoinCommit(tpm, &join_request.F, &R_str));

  EXPECT_EQ(kEpidNoErr, TpmJoin(tpm, &join_request.c, &join_request.s));
  EXPECT_EQ(kEpidOutOfSequenceError,
            TpmJoin(tpm, &join_request.c, &join_request.s));

  EXPECT_EQ(kEpidNoErr, TpmJoinCommit(tpm, &join_request.F, &R_str));
}

TEST_F(EpidTpmTest, TpmNrProveFollowedByTpmNrProveDisallowed) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  TpmCtxObj tpm(&Prng::Generate, &my_prng, epid2params);
  THROW_ON_EPIDERR(TpmProvision(tpm, &this->kMemberPrivateKey.f));

  G1ElemStr B_str = {0};
  G1ElemStr K_str = {0};
  SigRlEntry sigrl_entry = {0};
  NrProveCommitOutput commit_out;
  THROW_ON_EPIDERR(
      TpmNrProveCommit(tpm, &B_str, &K_str, &sigrl_entry, &commit_out));

  NrProof nr_proof;
  nr_proof.T = commit_out.T;

  EXPECT_EQ(kEpidNoErr,
            TpmNrProve(tpm, &nr_proof.c, &nr_proof.smu, &nr_proof.snu));
  EXPECT_EQ(kEpidOutOfSequenceError,
            TpmNrProve(tpm, &nr_proof.c, &nr_proof.smu, &nr_proof.snu));

  EXPECT_EQ(kEpidNoErr,
            TpmNrProveCommit(tpm, &B_str, &K_str, &sigrl_entry, &commit_out));
}

}  // namespace
