/*############################################################################
  # Copyright 2016-2020 Intel Corporation
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
/// Join Request related unit tests.
/*! \file */

#include <cstring>
#include <memory>
#include "gtest/gtest.h"
#include "testhelper/epid_gtest-testhelper.h"

extern "C" {
#include "common/epid2params.h"
#include "epid/member/api.h"
#include "ippmath/ecgroup.h"
#include "ippmath/finitefield.h"
#include "ippmath/memory.h"
}

#include "member-testhelper.h"
#include "testhelper/ecgroup_wrapper-testhelper.h"
#include "testhelper/ecpoint_wrapper-testhelper.h"
#include "testhelper/epid_params-testhelper.h"
#include "testhelper/errors-testhelper.h"
#include "testhelper/ffelement_wrapper-testhelper.h"
#include "testhelper/finite_field_wrapper-testhelper.h"
#include "testhelper/mem_params-testhelper.h"
#include "testhelper/prng-testhelper.h"
#include "testhelper/verifier_wrapper-testhelper.h"

/// compares FpElemStr values
bool operator==(FpElemStr const& lhs, FpElemStr const& rhs) {
  return 0 == std::memcmp(&lhs, &rhs, sizeof(lhs));
}

namespace {
// local constant for Join Request tests. This can be hoisted later if needed
// avoids cpplint warning about multiple includes.
const GroupPubKey kPubKey = {
#include "testhelper/testdata/grp01/gpubkey.inc"
};

/// Validates join request.
void ValidateJoinRequest(void* request, size_t request_size, HashAlg hash_alg,
                         GroupPubKey const& grp_public_key, FpElemStr const& f,
                         IssuerNonce const& ni) {
  Epid2Params params_values = {
#include "common/epid2params_ate.inc"
  };
  struct {
    G1ElemStr F;  /// an element in G1
    FpElemStr c;  /// an integer between [0, p-1]
    FpElemStr s;  /// an integer between [0, p-1]
  } joinreq_values;
  Epid20Params params;

  // h1^f ?= F
  EcPointObj F_expected(&params.G1, grp_public_key.h1);
  ASSERT_EQ(sizeof(joinreq_values), request_size);
  if (0 != memcpy_S(&joinreq_values, sizeof(joinreq_values), request,
                    request_size)) {
    THROW_ON_EPIDERR(kEpidBadArgErr);
  }
  THROW_ON_EPIDERR(EcExp(params.G1, F_expected, (BigNumStr*)&f, F_expected));
  ASSERT_EQ(*(G1ElemStr*)(F_expected.data().data()), joinreq_values.F);

  // H(p|g1|g2|h1|h2|w|F|R|ni) ?= c, where R = h1^s * F^(-c)
  FfElementObj nc(&params.fp, joinreq_values.c);
  THROW_ON_EPIDERR(FfNeg(params.fp, nc, nc));
  EcPointObj a(&params.G1, grp_public_key.h1);
  EcPointObj b(&params.G1, joinreq_values.F);
  THROW_ON_EPIDERR(EcExp(params.G1, a, (BigNumStr*)&joinreq_values.s, a));
  THROW_ON_EPIDERR(EcExp(params.G1, b, (BigNumStr*)nc.data().data(), b));
  THROW_ON_EPIDERR(EcMul(params.G1, a, b, a));

#pragma pack(1)
  struct {
    BigNumStr p;     // Intel(R) EPID 2.0 parameter p
    G1ElemStr g1;    // Intel(R) EPID 2.0 parameter g1
    G2ElemStr g2;    // Intel(R) EPID 2.0 parameter g2
    G1ElemStr h1;    // Group public key value h1
    G1ElemStr h2;    // Group public key value h2
    G2ElemStr w;     // Group public key value w
    G1ElemStr F;     // Variable F computed in algorithm
    G1ElemStr R;     // Variable R computed in algorithm
    IssuerNonce NI;  // Issuer Nonce
  } commitment_values = {params_values.p,
                         params_values.g1,
                         params_values.g2,
                         grp_public_key.h1,
                         grp_public_key.h2,
                         grp_public_key.w,
                         joinreq_values.F,
                         *(G1ElemStr*)(a.data().data()),
                         ni};
#pragma pack()

  FfElementObj commitment(&params.fp);
  THROW_ON_EPIDERR(FfHash(params.fp, &commitment_values,
                          sizeof commitment_values, hash_alg, commitment));
  ASSERT_EQ(*(FpElemStr*)(commitment.data().data()), joinreq_values.c);
}

TEST_F(EpidMemberTest, CreateJoinRequestFailsGivenNullParameters) {
  GroupPubKey pub_key = kPubKey;
  IssuerNonce ni;
  MemberParams params;
  Prng prng;
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  SetMemberParams(Prng::Generate, &prng, nullptr, &params);
  MemberCtxObj ctx(&params);
  EXPECT_EQ(kEpidBadArgErr,
            EpidCreateJoinRequest(nullptr, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_EQ(kEpidBadArgErr,
            EpidCreateJoinRequest(ctx, nullptr, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_EQ(kEpidBadArgErr,
            EpidCreateJoinRequest(ctx, &pub_key, nullptr, join_request.data(),
                                  join_request.size()));
  EXPECT_EQ(kEpidBadArgErr, EpidCreateJoinRequest(ctx, &pub_key, &ni, nullptr,
                                                  join_request.size()));
}

TEST_F(EpidMemberTest, CreateJoinRequestFailsRejectsRequestOfInsufficentSize) {
  Prng prng;
  MemberParams params = {0};
  GroupPubKey pub_key = kPubKey;
  pub_key.gid.data[1] = 0x02;  // sha512
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
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  SetMemberParams(Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoMemErr,
            EpidCreateJoinRequest(member, &pub_key, &ni,
                                  (JoinRequest*)join_request.data(), 0));

  EXPECT_EQ(kEpidNoMemErr,
            EpidCreateJoinRequest(member, &pub_key, &ni,
                                  (JoinRequest*)join_request.data(),
                                  EpidGetJoinRequestSize() - 1));
}

TEST_F(EpidMemberTest, CreateJoinRequestWorksGivenNoF) {
  GroupPubKey pub_key = kPubKey;
  IssuerNonce ni;
  MemberParams params;
  Prng prng;
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  SetMemberParams(Prng::Generate, &prng, nullptr, &params);
  MemberCtxObj ctx(&params);
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(ctx, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
}

TEST_F(EpidMemberTest, CreateJoinRequestFailsGivenInvalidGroupKey) {
  Prng prng;
  MemberParams params = {0};
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
  Epid20Params epid_params;
  EcPointObj pt(&epid_params.G1);
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  SetMemberParams(Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  ASSERT_NE(kEpidNoErr, ReadEcPoint(epid_params.G1, (uint8_t*)&pub_key.h1,
                                    sizeof(pub_key.h1), pt));
  EXPECT_EQ(kEpidBadArgErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
}

TEST_F(EpidMemberTest, CreateJoinRequestFailsGivenInvalidFValue) {
  Prng prng;
  MemberParams params = {0};
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
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  EpidStatus sts;
  SetMemberParams(Prng::Generate, &prng, &f, &params);

  std::unique_ptr<uint8_t[]> member;
  size_t context_size = 0;
  sts = EpidMemberGetSize(&params, &context_size);
  EXPECT_TRUE(kEpidNoErr == sts || kEpidBadArgErr == sts)
      << "Actual value " << sts;

  if (kEpidNoErr == sts) {
    member.reset(new uint8_t[context_size]());
    sts = EpidMemberInit(&params, (MemberCtx*)member.get());
    EXPECT_TRUE(kEpidNoErr == sts || kEpidBadArgErr == sts)
        << "Actual value " << sts;
  }

  if (kEpidNoErr == sts) {
    sts = EpidCreateJoinRequest((MemberCtx*)member.get(), &pub_key, &ni,
                                join_request.data(), join_request.size());
    EXPECT_EQ(kEpidBadArgErr, sts);
  }

  EpidMemberDeinit((MemberCtx*)member.get());
}

TEST_F(EpidMemberTest, CreateJoinRequestWorksUsingSha512) {
  Prng prng;
  MemberParams params = {0};
  GroupPubKey pub_key = kPubKey;
  pub_key.gid.data[1] = 0x02;  // sha512
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
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  SetMemberParams(Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
      join_request.data(), join_request.size(), kSha512, pub_key, f, ni));
}

TEST_F(EpidMemberTest, CreateJoinRequestWorksUsingSha256) {
  Prng prng;
  MemberParams params = {0};
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
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  SetMemberParams(Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
      join_request.data(), join_request.size(), kSha256, pub_key, f, ni));
}

TEST_F(EpidMemberTest,
       CreateJoinRequestGeneratesDiffJoinRequestsOnMultipleCalls) {
  Prng prng;
  MemberParams params = {0};
  GroupPubKey pub_key = kPubKey;  // sha256
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
  std::vector<uint8_t> join_request1(EpidGetJoinRequestSize());
  std::vector<uint8_t> join_request2(EpidGetJoinRequestSize());
  SetMemberParams(Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request1.data(),
                                  join_request1.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
      join_request1.data(), join_request1.size(), kSha256, pub_key, f, ni));
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request2.data(),
                                  join_request2.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
      join_request2.data(), join_request2.size(), kSha256, pub_key, f, ni));
  EXPECT_NE(join_request1, join_request2);
}

TEST_F(EpidMemberTest,
       CreateJoinRequestGeneratesDiffJoinRequestsGivenDiffHashAlgs) {
  MemberParams params = {0};
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
  std::vector<uint8_t> join_request1(EpidGetJoinRequestSize());
  std::vector<uint8_t> join_request2(EpidGetJoinRequestSize());
  // Ensure that two members created with equal seed and do not
  // interfere each other. Member1 is deleted by the time member2
  // is created.
  {
    Prng prng;
    SetMemberParams(Prng::Generate, &prng, &f, &params);
    MemberCtxObj member1(&params);
    prng.set_seed(0x1234);
    EXPECT_EQ(kEpidNoErr, EpidCreateJoinRequest(member1, &pub_key, &ni,
                                                join_request1.data(),
                                                join_request1.size()));
    EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
        join_request1.data(), join_request1.size(), kSha256, pub_key, f, ni));
  }
  {
    Prng prng;
    SetMemberParams(Prng::Generate, &prng, &f, &params);
    MemberCtxObj member2(&params);
    prng.set_seed(0x1234);
    pub_key.gid.data[1] = 0x02;  // set sha512
    EXPECT_EQ(kEpidNoErr, EpidCreateJoinRequest(member2, &pub_key, &ni,
                                                join_request2.data(),
                                                join_request2.size()));
    EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
        join_request2.data(), join_request2.size(), kSha512, pub_key, f, ni));
  }
  EXPECT_NE(join_request1, join_request2);
}

TEST_F(EpidMemberTest,
       CreateJoinRequestWorksGivenValidParametersUsingIKGFData) {
  Prng prng;
  MemberParams params = {0};
  const GroupPubKey* pub_key = reinterpret_cast<const GroupPubKey*>(
      this->kGroupPublicKeyDataIkgf.data());
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
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  SetMemberParams(Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
      join_request.data(), join_request.size(), kSha256, *pub_key, f, ni));
}

TEST_F(EpidMemberTest,
       ProvisionedMemberCanCreateJoinRequestForGroupWithDiffHashAlg) {
  Prng my_prng;
  // create and provision member in sha256 group
  GroupPubKey pub_key = this->kGroupPublicKey;
  PrivKey mpriv_key = this->kMemberPrivateKey;
  MemberParams params = {0};
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());

  SetMemberParams(&Prng::Generate, &my_prng, &mpriv_key.f, &params);
  MemberCtxObj member(&params);

  // provision into group with sha256
  EXPECT_EQ(kEpidNoErr, EpidProvisionKey(member, &pub_key, &mpriv_key,
                                         &this->kMemberPrecomp));

  // create join request into a group with a different hash alg
  // verify join request
  pub_key.gid.data[1] &= 0xf0;
  pub_key.gid.data[1] |= 0x01;  // sha384

  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(join_request.data(),
                                              join_request.size(), kSha384,
                                              pub_key, mpriv_key.f, ni));
}

TEST_F(EpidMemberTest, CanCreateMultipleJoinRequestsWithDiffHashAlgs) {
  Prng my_prng;
  // create member with specific f
  GroupPubKey pub_key = this->kGroupPublicKey;
  FpElemStr f = this->kMemberPrivateKey.f;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &my_prng, &f, &params);
  MemberCtxObj member(&params);
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());

  // create join request into a group with sha256 hash alg
  // verify join request
  pub_key.gid.data[1] &= 0xf0;
  pub_key.gid.data[1] |= 0x00;
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
      join_request.data(), join_request.size(), kSha256, pub_key, f, ni));

  // create join request into a group with sha384 hash alg
  // verify join request
  pub_key.gid.data[1] &= 0xf0;
  pub_key.gid.data[1] |= 0x01;
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
      join_request.data(), join_request.size(), kSha384, pub_key, f, ni));

  // create join request into a group with sha512 hash alg
  // verify join request
  pub_key.gid.data[1] &= 0xf0;
  pub_key.gid.data[1] |= 0x02;
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
      join_request.data(), join_request.size(), kSha512, pub_key, f, ni));

  // create join request into a group with sha512_256 hash alg
  // verify join request
  pub_key.gid.data[1] &= 0xf0;
  pub_key.gid.data[1] |= 0x03;
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
      join_request.data(), join_request.size(), kSha512_256, pub_key, f, ni));
}

TEST_F(EpidMemberTest, CreateJoinRequestDoesNotChangeHashAlgorithm) {
  Prng my_prng;
  // create and provision member in sha256 group
  MemberCtxObj member(this->kGroupPublicKey, this->kMemberPrivateKey,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());

  // create join request into a group with a different hash alg
  GroupPubKey pub_key = kPubKey;
  pub_key.gid.data[1] &= 0xf0;
  pub_key.gid.data[1] |= 0x01;  // sha384
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));

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
