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
  #############
  ###############################################################*/
/// Tpm2Commit unit tests.
/*! \file */

#include "tpm2-testhelper.h"
#include "gtest/gtest.h"
#include "testhelper/ecpoint_wrapper-testhelper.h"
#include "testhelper/epid2params_wrapper-testhelper.h"
#include "testhelper/epid_params-testhelper.h"
#include "testhelper/errors-testhelper.h"
#include "testhelper/ffelement_wrapper-testhelper.h"
#include "testhelper/prng-testhelper.h"

extern "C" {
#include "common/endian_convert.h"
#include "epid/member/split/tpm2/commit.h"
#include "epid/member/split/tpm2/context.h"
#include "epid/member/split/tpm2/flushcontext.h"
#include "epid/member/split/tpm2/load_external.h"
#include "epid/member/split/tpm2/sign.h"
}

namespace {

TEST_F(EpidTpm2Test, CommitFailsGivenNullParameters) {
  Epid20Params params;
  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  EcPointObj p1(&params.G1, this->kP1Str);
  FfElementObj y2(&params.fq, this->kY2Sha256Str);
  uint16_t counter = 0;

  Prng my_prng;
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, &this->kMemberFValue, epid2params);
  Tpm2Key* f_handle;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(tpm, kSha256, &this->kMemberFValue, &f_handle));

  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Commit(nullptr, f_handle, p1, this->kS2Sha256.data(),
                       this->kS2Sha256.size(), y2, k, l, e, &counter));
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Commit(tpm, nullptr, p1, this->kS2Sha256.data(),
                       this->kS2Sha256.size(), y2, k, l, e, &counter));
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Commit(tpm, f_handle, p1, nullptr, this->kS2Sha256.size(), y2,
                       k, l, e, &counter));
  // Testing step a of the "C.2.3 Tpm2Commit()"
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Commit(tpm, f_handle, p1, this->kS2Sha256.data(),
                       this->kS2Sha256.size(), nullptr, k, l, e, &counter));
  // Testing step a of the "C.2.3 Tpm2Commit()"
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Commit(tpm, f_handle, p1, this->kS2Sha256.data(),
                       this->kS2Sha256.size(), y2, nullptr, l, e, &counter));
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Commit(tpm, f_handle, p1, this->kS2Sha256.data(),
                       this->kS2Sha256.size(), y2, k, nullptr, e, &counter));
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Commit(tpm, f_handle, p1, this->kS2Sha256.data(),
                       this->kS2Sha256.size(), y2, k, l, nullptr, &counter));
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Commit(tpm, f_handle, p1, this->kS2Sha256.data(),
                       this->kS2Sha256.size(), y2, k, l, e, nullptr));
}

TEST_F(EpidTpm2Test, CommitFailsGivenInvalidLength) {
  Epid20Params params;
  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  EcPointObj p1(&params.G1, this->kP1Str);
  FfElementObj y2(&params.fq, this->kY2Sha256Str);
  uint16_t counter = 0;

  Prng my_prng;
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, &this->kMemberFValue, epid2params);
  Tpm2Key* f_handle;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(tpm, kSha256, &this->kMemberFValue, &f_handle));

  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Commit(tpm, f_handle, p1, this->kS2Sha256.data(), 0, y2, k, l,
                       e, &counter));
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Commit(tpm, f_handle, p1, this->kS2Sha256.data(),
                       sizeof(uint16_t) - 1, y2, k, l, e, &counter));
}

TEST_F(EpidTpm2Test, CommitFailsIfKeyNotSet) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, NULL, epid2params);

  Tpm2Key* f_handle;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(tpm, kSha256, &this->kMemberFValue, &f_handle));
  THROW_ON_EPIDERR(Tpm2FlushContext(tpm, &f_handle));

  Epid20Params params;
  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  EcPointObj p1(&params.G1, this->kP1Str);
  FfElementObj y2(&params.fq, this->kY2Sha256Str);
  uint16_t counter = 0;
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Commit(tpm, f_handle, p1, this->kS2Sha256.data(),
                       this->kS2Sha256.size(), y2, k, l, e, &counter));
}

TEST_F(EpidTpm2Test, CommitFailsGivenS2y2NotOnCurve) {
  // Testing step d of the "C.2.3 Tpm2Commit()"
  Epid20Params params;
  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  EcPointObj p1(&params.G1, this->kP1Str);
  FqElemStr invalid_kY2Sha256Str = this->kY2Sha256Str;
  invalid_kY2Sha256Str.data.data[31]++;  // make point not belong to the group
  FfElementObj invalid_y2(&params.fq, invalid_kY2Sha256Str);
  uint16_t counter = 0;

  Prng my_prng;
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, &this->kMemberFValue, epid2params);
  Tpm2Key* f_handle;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(tpm, kSha256, &this->kMemberFValue, &f_handle));

  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Commit(tpm, f_handle, p1, this->kS2Sha256.data(),
                       this->kS2Sha256.size(), invalid_y2, k, l, e, &counter));
}

TEST_F(EpidTpm2Test, CommitFailsIfResultIsAtInfinity) {
  // Testing step l of the "C.2.3 Tpm2Commit()"
  Epid20Params params;
  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  G1ElemStr infinity_str = {0};
  EcPointObj infinity(&params.G1, infinity_str);
  FfElementObj y2(&params.fq, this->kY2Sha256Str);
  uint16_t counter = 0;

  Prng my_prng;
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&Prng::Generate, &my_prng, &this->kMemberFValue, epid2params);
  Tpm2Key* f_handle;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(tpm, kSha256, &this->kMemberFValue, &f_handle));

  EXPECT_EQ(kEpidBadArgErr,
            Tpm2Commit(tpm, f_handle, infinity, this->kS2Sha256.data(),
                       this->kS2Sha256.size(), y2, k, l, e, &counter));
}

TEST_F(EpidTpm2Test, CommitCanUseKeyLoadedByLoadExternal) {
  Prng prng;
  Epid2ParamsObj epid2params;
  Epid20Params params;
  FpElemStr f_str = this->kMemberFValue;
  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  FfElementObj y2(&params.fq, this->kY2Sha256Str);
  uint16_t counter = 0;
  Tpm2CtxObj tpm(&Prng::Generate, &prng, &f_str, epid2params);
  Tpm2Key* f_handle;
  EXPECT_EQ(kEpidNoErr, Tpm2LoadExternal(tpm, kSha256, &f_str, &f_handle));

  EXPECT_EQ(kEpidNoErr,
            Tpm2Commit(tpm, f_handle, nullptr, this->kS2Sha256.data(),
                       this->kS2Sha256.size(), y2, k, l, e, &counter));
  THROW_ON_EPIDERR(Tpm2ReleaseCounter(tpm, counter, f_handle));

  // k = (x2, y2) ^ f, where x2 = Hash(s2)
  G1ElemStr k_str;
  THROW_ON_EPIDERR(WriteEcPoint(params.G1, k, &k_str, sizeof(k_str)));
  EXPECT_EQ(this->kP2Sha256ExpF, k_str);
}

TEST_F(EpidTpm2Test, CommitReturnsSameLEForSameP1P2) {
  Prng prng;
  Epid2ParamsObj epid2params;
  Epid20Params params;
  FpElemStr f_str = this->kMemberFValue;
  // create TPM context
  Tpm2CtxObj tpm(&Prng::Generate, &prng, &f_str, epid2params);
  // load f value
  Tpm2Key* f_handle;
  EXPECT_EQ(kEpidNoErr, Tpm2LoadExternal(tpm, kSha256, &f_str, &f_handle));

  // commit(P1=p2, P2=p2) => k = p2^f, l = p2^r, e = p2^r
  FfElementObj y2(&params.fq, this->kY2Sha256Str);
  EcPointObj p2(&params.G1, kP2Sha256Str);
  EcPointObj p2_exp_f(&params.G1, kP2Sha256ExpF);

  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  uint16_t counter = 0;
  EXPECT_EQ(kEpidNoErr,
            Tpm2Commit(tpm, f_handle, p2, this->kS2Sha256.data(),
                       this->kS2Sha256.size(), y2, k, l, e, &counter));
  THROW_ON_EPIDERR(Tpm2ReleaseCounter(tpm, counter, f_handle));

  G1ElemStr l_str, e_str;
  THROW_ON_EPIDERR(WriteEcPoint(params.G1, l, &l_str, sizeof(l_str)));
  THROW_ON_EPIDERR(WriteEcPoint(params.G1, e, &e_str, sizeof(e_str)));
  EXPECT_EQ(l_str, e_str);
}

TEST_F(EpidTpm2Test, CommitCanBeUsedTwice) {
  Prng prng;
  Epid2ParamsObj epid2params;
  Epid20Params params;
  FpElemStr f_str = this->kMemberFValue;
  // create TPM context
  Tpm2CtxObj tpm(&Prng::Generate, &prng, &f_str, epid2params);
  // load f value
  Tpm2Key* f_handle;
  EXPECT_EQ(kEpidNoErr, Tpm2LoadExternal(tpm, kSha256, &f_str, &f_handle));

  EcPointObj p1(&params.G1, this->kP1Str);
  EcPointObj e(&params.G1);
  uint16_t ctr1 = 0, ctr2 = 0;

  EXPECT_EQ(kEpidNoErr, Tpm2Commit(tpm, f_handle, p1, nullptr, 0, nullptr,
                                   nullptr, nullptr, e, &ctr1));

  EXPECT_EQ(kEpidNoErr, Tpm2Commit(tpm, f_handle, p1, nullptr, 0, nullptr,
                                   nullptr, nullptr, e, &ctr2));
  THROW_ON_EPIDERR(Tpm2ReleaseCounter(tpm, ctr1, f_handle));
  THROW_ON_EPIDERR(Tpm2ReleaseCounter(tpm, ctr2, f_handle));
}
TEST_F(EpidTpm2Test, CommitCanUseHashFromEcHashSha256) {
  HashAlg halg = kSha256;
  Prng prng;
  Epid2ParamsObj epid2params;
  FpElemStr f_str = this->kMemberFValue;
  Tpm2CtxObj tpm(&Prng::Generate, &prng, &f_str, epid2params);
  Epid20Params params;
  EcPointObj R(&params.G1), k(&params.G1), l(&params.G1), e(&params.G1);
  FfElementObj y(&params.fq);
  uint32_t i = 0;
  uint16_t counter = 0;
  G1ElemStr R_str = {0};
  std::vector<uint8_t> bsn = {'b', 's', 'n', '0'};
  Tpm2Key* f_handle;
  EXPECT_EQ(kEpidNoErr, Tpm2LoadExternal(tpm, halg, &f_str, &f_handle));

  EXPECT_EQ(kEpidNoErr,
            EcHash(epid2params.G1(), bsn.data(), bsn.size(), halg, R, &i));
  i = ntohl(i);
  THROW_ON_EPIDERR(WriteEcPoint(epid2params.G1(), R, &R_str, sizeof(R_str)));
  THROW_ON_EPIDERR(
      ReadFfElement(params.fq.get(), &R_str.y, sizeof(R_str.y), y));

  std::vector<uint8_t> digest((uint8_t*)&i, (uint8_t*)&i + sizeof(i));
  digest.reserve(digest.size() + bsn.size());
  digest.insert(digest.end(), bsn.begin(), bsn.end());
  EXPECT_EQ(kEpidNoErr, Tpm2Commit(tpm, f_handle, nullptr, digest.data(),
                                   digest.size(), y, k, l, e, &counter));
  Tpm2ReleaseCounter(tpm, counter, f_handle);
}
#ifndef TPM_TSS
TEST_F(EpidTpm2Test, CommitCanUseHashFromEcHashSha384) {
  HashAlg halg = kSha384;
  Prng prng;
  Epid2ParamsObj epid2params;
  FpElemStr f_str = this->kMemberFValue;
  Tpm2CtxObj tpm(&Prng::Generate, &prng, &f_str, epid2params);
  Epid20Params params;
  EcPointObj R(&params.G1), k(&params.G1), l(&params.G1), e(&params.G1);
  FfElementObj y(&params.fq);
  uint32_t i = 0;
  uint16_t counter = 0;
  G1ElemStr R_str = {0};
  std::vector<uint8_t> bsn = {'b', 's', 'n', '0'};
  Tpm2Key* f_handle;
  EXPECT_EQ(kEpidNoErr, Tpm2LoadExternal(tpm, halg, &f_str, &f_handle));

  EXPECT_EQ(kEpidNoErr,
            EcHash(epid2params.G1(), bsn.data(), bsn.size(), halg, R, &i));
  i = ntohl(i);
  THROW_ON_EPIDERR(WriteEcPoint(epid2params.G1(), R, &R_str, sizeof(R_str)));
  THROW_ON_EPIDERR(
      ReadFfElement(params.fq.get(), &R_str.y, sizeof(R_str.y), y));

  std::vector<uint8_t> digest((uint8_t*)&i, (uint8_t*)&i + sizeof(i));
  digest.reserve(digest.size() + bsn.size());
  digest.insert(digest.end(), bsn.begin(), bsn.end());
  EXPECT_EQ(kEpidNoErr, Tpm2Commit(tpm, f_handle, nullptr, digest.data(),
                                   digest.size(), y, k, l, e, &counter));
  Tpm2ReleaseCounter(tpm, counter, f_handle);
}
TEST_F(EpidTpm2Test, CommitCanUseHashFromEcHashSha512) {
  HashAlg halg = kSha512;
  Prng prng;
  Epid2ParamsObj epid2params;
  FpElemStr f_str = this->kMemberFValue;
  Tpm2CtxObj tpm(&Prng::Generate, &prng, &f_str, epid2params);
  Epid20Params params;
  EcPointObj R(&params.G1), k(&params.G1), l(&params.G1), e(&params.G1);
  FfElementObj y(&params.fq);
  uint32_t i = 0;
  uint16_t counter = 0;
  G1ElemStr R_str = {0};
  std::vector<uint8_t> bsn = {'b', 's', 'n', '0'};
  Tpm2Key* f_handle;
  EXPECT_EQ(kEpidNoErr, Tpm2LoadExternal(tpm, halg, &f_str, &f_handle));

  EXPECT_EQ(kEpidNoErr,
            EcHash(epid2params.G1(), bsn.data(), bsn.size(), halg, R, &i));
  i = ntohl(i);
  THROW_ON_EPIDERR(WriteEcPoint(epid2params.G1(), R, &R_str, sizeof(R_str)));
  THROW_ON_EPIDERR(
      ReadFfElement(params.fq.get(), &R_str.y, sizeof(R_str.y), y));

  std::vector<uint8_t> digest((uint8_t*)&i, (uint8_t*)&i + sizeof(i));
  digest.reserve(digest.size() + bsn.size());
  digest.insert(digest.end(), bsn.begin(), bsn.end());
  EXPECT_EQ(kEpidNoErr, Tpm2Commit(tpm, f_handle, nullptr, digest.data(),
                                   digest.size(), y, k, l, e, &counter));
  Tpm2ReleaseCounter(tpm, counter, f_handle);
}
#endif  // TPM_TSS
}  // namespace
