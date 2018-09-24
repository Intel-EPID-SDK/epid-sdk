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
/// TPM Sign unit tests.
/*! \file */
#include <climits>

#include "gtest/gtest.h"

#include "epid/common-testhelper/epid2params_wrapper-testhelper.h"
#include "epid/common-testhelper/epid_params-testhelper.h"
#include "epid/common-testhelper/errors-testhelper.h"
#include "epid/common-testhelper/prng-testhelper.h"
#include "epid/member/split/tpm2/unittests/tpm2-testhelper.h"

extern "C" {
#include "epid/common/src/hashsize.h"
#include "epid/common/src/memory.h"
#include "epid/member/split/tpm2/commit.h"
#include "epid/member/split/tpm2/flushcontext.h"
#include "epid/member/split/tpm2/load_external.h"
#include "epid/member/split/tpm2/sign.h"
}

namespace {
//////////////////////////////////////////////////////////////////////////

/// Storage for values to create commitment in NrProve algorithm
/// Sha Digest Element
typedef union sha_digest {
  uint8_t sha512_digest[EPID_SHA512_DIGEST_BITSIZE / CHAR_BIT];
  uint8_t sha384_digest[EPID_SHA384_DIGEST_BITSIZE / CHAR_BIT];
  uint8_t sha256_digest[EPID_SHA256_DIGEST_BITSIZE / CHAR_BIT];
  uint8_t digest[1];  ///< Pointer to digest
} sha_digest;

#pragma pack(1)
typedef struct Tpm2SignCommitValues {
  BigNumStr noncek;  //!< random number (256-bit)
  sha_digest digest;
} Tpm2SignCommitValues;
#pragma pack()

// Tpm2Sign Tests
// Verify signature computed by TPM ECDAA scheme:
// 0 < sign_k < p
// point^sign_s ?= random_exp * private_exp^hash(signk||digest)
bool IsSignatureValid(void const* digest, size_t digest_len,
                      FfElement const* sign_k, FfElement const* sign_s,
                      EcPoint const* point, EcPoint const* private_exp,
                      EcPoint const* random_exp, HashAlg hash_alg) {
  BigNumStr exp;
  bool is_k_zero = true;
  Epid20Params params;
  FfElementObj c(&params.fp);
  EcPointObj v1(&params.G1);
  Tpm2SignCommitValues tpm2sign_hash_commit = {0};

  // 0 < k < p
  THROW_ON_EPIDERR(FfIsZero(params.fp, sign_k, &is_k_zero));
  if (is_k_zero) {
    THROW_ON_EPIDERR(kEpidErr);
  }
  // c = hash(k||digest)
  THROW_ON_EPIDERR(WriteFfElement(params.fp, sign_k,
                                  &tpm2sign_hash_commit.noncek,
                                  sizeof(tpm2sign_hash_commit.noncek)));
  size_t commit_hash_len = sizeof(tpm2sign_hash_commit.noncek) + digest_len;
  if (digest) {
    if (sizeof(tpm2sign_hash_commit.digest) < digest_len) {
      THROW_ON_EPIDERR(kEpidBadArgErr);
    }
    // Memory copy is used to copy a message of variable length
    if (0 != memcpy_S(&tpm2sign_hash_commit.digest, digest_len, digest,
                      digest_len)) {
      THROW_ON_EPIDERR(kEpidBadArgErr);
    }
  }
  THROW_ON_EPIDERR(
      FfHash(params.fp, &tpm2sign_hash_commit, commit_hash_len, hash_alg, c));
  THROW_ON_EPIDERR(WriteFfElement(params.fp, c, &exp, sizeof(exp)));
  THROW_ON_EPIDERR(EcExp(params.G1, private_exp, &exp, v1));
  // v1 = p^k * p^(f*c)
  THROW_ON_EPIDERR(EcMul(params.G1, random_exp, v1, v1));
  // v2 = p2^s
  EcPointObj v2(&params.G1);
  THROW_ON_EPIDERR(WriteFfElement(params.fp, sign_s, &exp, sizeof(exp)));
  THROW_ON_EPIDERR(EcExp(params.G1, point, &exp, v2));

  // v1 ?= v2
  G1ElemStr v1_str, v2_str;
  THROW_ON_EPIDERR(WriteEcPoint(params.G1, v1, &v1_str, sizeof(v1_str)));
  THROW_ON_EPIDERR(WriteEcPoint(params.G1, v2, &v2_str, sizeof(v2_str)));
  return v1_str == v2_str;
}

TEST_F(EpidTpm2Test, SignProducesValidSignatureUsingSha256Digest) {
  Epid20Params params;

  // create TPM context
  Prng my_prng;
  Epid2ParamsObj epid2params;
  FpElemStr f = this->kMemberFValue;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, &f, epid2params);
  // load f value
  Tpm2Key* f_handle;
  EXPECT_EQ(kEpidNoErr, Tpm2LoadExternal(tpm, kSha256, &f, &f_handle));

  // commit(P1=p2, P2=p2) => k = p2^f, l = p2^r, e = p2^r
  FfElementObj y2(&params.fq, this->kY2Sha256Str);
  EcPointObj p2(&params.G1, kP2Sha256Str);

  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  uint16_t counter = 0;
  EXPECT_EQ(kEpidNoErr,
            Tpm2Commit(tpm, f_handle, p2, this->kS2Sha256.data(),
                       this->kS2Sha256.size(), y2, k, l, e, &counter));

  // sign(digest) => sign_k = sign_k, sign_s = r + c * f,
  //   where c = H(sign_k||digest)
  FfElementObj sign_k(&params.fp), sign_s(&params.fp);
  EXPECT_EQ(kEpidNoErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha256,
                     sizeof(this->kDigestSha256), counter, sign_k, sign_s));

  EXPECT_TRUE(IsSignatureValid(this->kDigestSha256, sizeof(this->kDigestSha256),
                               sign_k, sign_s, p2, k, l, kSha256));
}

TEST_F(EpidTpm2Test, SignProducesValidSignatureUsingSha384Digest) {
  Epid20Params params;

  // create TPM context
  Prng my_prng;
  Epid2ParamsObj epid2params;
  FpElemStr f = this->kMemberFValue;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, &f, epid2params);
  // load f value
  Tpm2Key* f_handle;
  EXPECT_EQ(kEpidNoErr, Tpm2LoadExternal(tpm, kSha384, &f, &f_handle));

  // commit(P1=p2, P2=p2) => k = p2^f, l = p2^r, e = p2^r
  FfElementObj y2(&params.fq, this->kY2Sha384Str);
  EcPointObj p2(&params.G1, kP2Sha384Str);

  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  uint16_t counter = 0;
  EXPECT_EQ(kEpidNoErr,
            Tpm2Commit(tpm, f_handle, p2, this->kS2Sha384.data(),
                       this->kS2Sha384.size(), y2, k, l, e, &counter));

  // sign(digest) => sign_k = sign_k, sign_s = r + c * f,
  //   where c = H(sign_k||digest)
  FfElementObj sign_k(&params.fp), sign_s(&params.fp);
  EXPECT_EQ(kEpidNoErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha384,
                     sizeof(this->kDigestSha384), counter, sign_k, sign_s));

  EXPECT_TRUE(IsSignatureValid(this->kDigestSha384, sizeof(this->kDigestSha384),
                               sign_k, sign_s, p2, k, l, kSha384));
}

TEST_F(EpidTpm2Test, SignProducesValidSignatureUsingSha512Digest) {
  Epid20Params params;

  // create TPM context
  Prng my_prng;
  Epid2ParamsObj epid2params;
  FpElemStr f = this->kMemberFValue;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, &f, epid2params);
  // load f value
  Tpm2Key* f_handle;
  EXPECT_EQ(kEpidNoErr, Tpm2LoadExternal(tpm, kSha512, &f, &f_handle));

  // commit(P1=p2, P2=p2) => k = p2^f, l = p2^r, e = p2^r
  FfElementObj y2(&params.fq, this->kY2Sha512Str);
  EcPointObj p2(&params.G1, kP2Sha512Str);

  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  uint16_t counter = 0;
  EXPECT_EQ(kEpidNoErr,
            Tpm2Commit(tpm, f_handle, p2, this->kS2Sha512.data(),
                       this->kS2Sha512.size(), y2, k, l, e, &counter));

  // sign(digest) => sign_k = sign_k, sign_s = r + c * f,
  //   where c = H(sign_k||digest)
  FfElementObj sign_k(&params.fp), sign_s(&params.fp);
  EXPECT_EQ(kEpidNoErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha512,
                     sizeof(this->kDigestSha512), counter, sign_k, sign_s));

  EXPECT_TRUE(IsSignatureValid(this->kDigestSha512, sizeof(this->kDigestSha512),
                               sign_k, sign_s, p2, k, l, kSha512));
}

TEST_F(EpidTpm2Test, SignProducesValidSignatureTwoTimes) {
  Epid20Params params;

  // create TPM context
  Prng my_prng;
  Epid2ParamsObj epid2params;
  FpElemStr f = this->kMemberFValue;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, &f, epid2params);
  // load f value
  Tpm2Key* f_handle;
  EXPECT_EQ(kEpidNoErr, Tpm2LoadExternal(tpm, kSha256, &f, &f_handle));

  // commit(P1=p2, P2=p2) => k = p2^f, l = p2^r, e = p2^r
  FfElementObj y2(&params.fq, this->kY2Sha256Str);
  EcPointObj p2(&params.G1, kP2Sha256Str);

  EcPointObj k1(&params.G1), l1(&params.G1), e1(&params.G1);
  EcPointObj k2(&params.G1), l2(&params.G1), e2(&params.G1);
  uint16_t ctr1 = 0, ctr2 = 0;
  EXPECT_EQ(kEpidNoErr,
            Tpm2Commit(tpm, f_handle, p2, this->kS2Sha256.data(),
                       this->kS2Sha256.size(), y2, k1, l1, e1, &ctr1));
  EXPECT_EQ(kEpidNoErr,
            Tpm2Commit(tpm, f_handle, p2, this->kS2Sha256.data(),
                       this->kS2Sha256.size(), y2, k2, l2, e2, &ctr2));

  // sign(digest) => sign_k = sign_k, sign_s = r + c * f,
  //   where c = H(sign_k||digest)
  FfElementObj sign_k1(&params.fp), sign_s1(&params.fp);
  FfElementObj sign_k2(&params.fp), sign_s2(&params.fp);
  EXPECT_EQ(kEpidNoErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha256,
                     sizeof(this->kDigestSha256), ctr1, sign_k1, sign_s1));
  EXPECT_EQ(kEpidNoErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha256,
                     sizeof(this->kDigestSha256), ctr2, sign_k2, sign_s2));

  EXPECT_TRUE(IsSignatureValid(this->kDigestSha256, sizeof(this->kDigestSha256),
                               sign_k1, sign_s1, p2, k1, l1, kSha256));
  EXPECT_TRUE(IsSignatureValid(this->kDigestSha256, sizeof(this->kDigestSha256),
                               sign_k2, sign_s2, p2, k2, l2, kSha256));
}

TEST_F(EpidTpm2Test, SignFailsGivenNullParameters) {
  Epid20Params params;
  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  FfElementObj sig_k(&params.fp), sig_s(&params.fp);
  uint16_t counter = 0;

  Prng my_prng;
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, &this->kMemberFValue, epid2params);
  Tpm2Key* f_handle;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(tpm, kSha256, &this->kMemberFValue, &f_handle));
  THROW_ON_EPIDERR(Tpm2Commit(tpm, f_handle, nullptr, nullptr, 0, nullptr, k, l,
                              e, &counter));

  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Sign(nullptr, f_handle, this->kDigestSha256,
                     sizeof(this->kDigestSha256), counter, sig_k, sig_s));
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Sign(tpm, nullptr, this->kDigestSha256,
                     sizeof(this->kDigestSha256), counter, sig_k, sig_s));
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Sign(tpm, f_handle, nullptr, sizeof(this->kDigestSha256),
                     counter, sig_k, sig_s));
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha256,
                     sizeof(this->kDigestSha256), counter, sig_k, nullptr));
}

TEST_F(EpidTpm2Test, SignFailsGivenInvalidDigestLen) {
  Epid20Params params;
  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  FfElementObj sig_k(&params.fp), sig_s(&params.fp);
  uint16_t counter = 0;

  Prng my_prng;
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, &this->kMemberFValue, epid2params);
  Tpm2Key* f_handle;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(tpm, kSha256, &this->kMemberFValue, &f_handle));
  THROW_ON_EPIDERR(Tpm2Commit(tpm, f_handle, nullptr, nullptr, 0, nullptr, k, l,
                              e, &counter));

  uint8_t digest[EPID_SHA256_DIGEST_BITSIZE / CHAR_BIT + 1] = {0};
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Sign(tpm, f_handle, digest, 0, counter, sig_k, sig_s));
  EXPECT_EQ(kEpidBadArgErr, Tpm2Sign(tpm, f_handle, digest,
                                     EPID_SHA256_DIGEST_BITSIZE / CHAR_BIT + 1,
                                     counter, sig_k, sig_s));
  EXPECT_EQ(kEpidBadArgErr, Tpm2Sign(tpm, f_handle, digest,
                                     EPID_SHA256_DIGEST_BITSIZE / CHAR_BIT - 1,
                                     counter, sig_k, sig_s));
}

TEST_F(EpidTpm2Test, SignFailsGivenUnrecognizedCounter) {
  Epid20Params params;
  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  FfElementObj sig_k(&params.fp), sig_s(&params.fp);
  uint16_t counter = 0;
  uint16_t zero = 0;
  uint16_t one = 1;
  uint16_t minus_one = (uint16_t)-1;

  Prng my_prng;
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, &this->kMemberFValue, epid2params);
  Tpm2Key* f_handle;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(tpm, kSha256, &this->kMemberFValue, &f_handle));

  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha256,
                     sizeof(this->kDigestSha256), zero, sig_k, sig_s));
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha256,
                     sizeof(this->kDigestSha256), one, sig_k, sig_s));
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha256,
                     sizeof(this->kDigestSha256), minus_one, sig_k, sig_s));

  THROW_ON_EPIDERR(Tpm2Commit(tpm, f_handle, nullptr, nullptr, 0, nullptr, k, l,
                              e, &counter));

  uint16_t counter_plus_1 = counter + 1;
  EXPECT_EQ(kEpidBadArgErr, Tpm2Sign(tpm, f_handle, this->kDigestSha256,
                                     sizeof(this->kDigestSha256),
                                     counter_plus_1, sig_k, sig_s));
  THROW_ON_EPIDERR(Tpm2ReleaseCounter(tpm, counter, f_handle));
}

TEST_F(EpidTpm2Test, SignFailsGivenPreviouslyUsedCounter) {
  Epid20Params params;
  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  FfElementObj sig_k(&params.fp), sig_s(&params.fp);
  uint16_t counter = 0;

  Prng my_prng;
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, &this->kMemberFValue, epid2params);
  Tpm2Key* f_handle;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(tpm, kSha256, &this->kMemberFValue, &f_handle));
  THROW_ON_EPIDERR(Tpm2Commit(tpm, f_handle, nullptr, nullptr, 0, nullptr, k, l,
                              e, &counter));

  EXPECT_EQ(kEpidNoErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha256,
                     sizeof(this->kDigestSha256), counter, sig_k, sig_s));
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha256,
                     sizeof(this->kDigestSha256), counter, sig_k, sig_s));
}

TEST_F(EpidTpm2Test, SignFailsIfKeyNotSet) {
  Epid20Params params;
  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  FfElementObj sig_k(&params.fp), sig_s(&params.fp);
  uint16_t counter = 0;

  Prng my_prng;
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, nullptr, epid2params);
  Tpm2Key* f_handle;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(tpm, kSha256, &this->kMemberFValue, &f_handle));
  THROW_ON_EPIDERR(Tpm2FlushContext(tpm, &f_handle));
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha256,
                     sizeof(this->kDigestSha256), counter, sig_k, sig_s));
}

//////////////////////////////////////////////////////////////////////////
// Tpm2ReleaseCounter Tests
TEST_F(EpidTpm2Test, ReleaseCounterFailsGivenNullPtr) {
  // create TPM context
  Prng my_prng;
  Epid2ParamsObj epid2params;
  FpElemStr f = this->kMemberFValue;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, &f, epid2params);
  uint16_t ctr = 0;

  Tpm2Key* f_handle;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(tpm, kSha256, &this->kMemberFValue, &f_handle));
  EXPECT_EQ(kEpidBadArgErr, Tpm2ReleaseCounter(nullptr, ctr, f_handle));
}
TEST_F(EpidTpm2Test, ReleaseCounterSuccessfullyReleasesCounter) {
  Epid20Params params;

  // create TPM context
  Prng my_prng;
  Epid2ParamsObj epid2params;
  FpElemStr f = this->kMemberFValue;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, &f, epid2params);
  // load f value
  Tpm2Key* f_handle;
  EXPECT_EQ(kEpidNoErr, Tpm2LoadExternal(tpm, kSha256, &f, &f_handle));

  // commit(P1=p2, P2=p2) => k = p2^f, l = p2^r, e = p2^r
  FfElementObj y2(&params.fq, this->kY2Sha256Str);
  EcPointObj p2(&params.G1, kP2Sha256Str);
  EcPointObj p2_exp_f(&params.G1, kP2Sha256ExpF);

  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  uint16_t counter = 0;
  EXPECT_EQ(kEpidNoErr,
            Tpm2Commit(tpm, f_handle, p2, this->kS2Sha256.data(),
                       this->kS2Sha256.size(), y2, k, l, e, &counter));
  EXPECT_EQ(kEpidNoErr, Tpm2ReleaseCounter(tpm, counter, f_handle));

  // sign(digest) => sign_k = sign_k, sign_s = r + c * f,
  //   where c = H(sign_k||digest)
  FfElementObj sign_k(&params.fp), sign_s(&params.fp);
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha256,
                     sizeof(this->kDigestSha256), counter, sign_k, sign_s));
}

}  // namespace
