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
#include "gtest/gtest.h"

#include "epid/common-testhelper/epid2params_wrapper-testhelper.h"
#include "epid/common-testhelper/epid_params-testhelper.h"
#include "epid/common-testhelper/errors-testhelper.h"
#include "epid/common-testhelper/prng-testhelper.h"
#include "epid/member/split/tpm2/unittests/onetimepad.h"
#include "epid/member/split/tpm2/unittests/tpm2-testhelper.h"

extern "C" {
#include "epid/common/src/memory.h"
#include "epid/member/split/tpm2/commit.h"
#include "epid/member/split/tpm2/load_external.h"
#include "epid/member/split/tpm2/sign.h"
}

namespace {
//////////////////////////////////////////////////////////////////////////
// Tpm2Sign Tests

TEST_F(EpidTpm2Test, SignProducesKnownSignatureUsingSha256Digest) {
  Epid20Params params;
  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  FfElementObj sig_k(&params.fp), sig_s(&params.fp);
  uint16_t counter = 0;

  OneTimePad my_prng;
  my_prng.InitUint8({
      // nonce randomized by commit
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
      0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9E, 0x0C, 0xDC, 0x65, 0xFB,
      0x12, 0x99, 0x92, 0x1A, 0xF6, 0x2D, 0x53, 0x6C, 0xD1, 0x0B, 0x50, 0x0C,
      // noncek randomized by sign
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x2D, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
      0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9E, 0x0C, 0xDC, 0x65, 0xFB,
      0x12, 0x99, 0x92, 0x1A, 0xF6, 0x2D, 0x53, 0x6C, 0xD1, 0x0B, 0x50, 0x0C,
  });
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&OneTimePad::Generate, &my_prng, &this->kMemberFValue,
                 epid2params);
  Tpm2Key* f_handle;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(tpm, kSha256, &this->kMemberFValue, &f_handle));
  THROW_ON_EPIDERR(Tpm2Commit(tpm, f_handle, nullptr, nullptr, 0, nullptr, k, l,
                              e, &counter));

  EXPECT_EQ(kEpidNoErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha256,
                     sizeof(this->kDigestSha256), counter, sig_k, sig_s));

  FpElemStr actual_s = {0};
  FpElemStr actual_k = {0};
  FpElemStr expected_s = {0xE1, 0x05, 0xB1, 0xE7, 0x69, 0x90, 0xE8, 0x12,
                          0x8F, 0x98, 0xA3, 0xAA, 0xA9, 0x1C, 0x73, 0x49,
                          0x79, 0xC3, 0xB7, 0x65, 0xAE, 0x81, 0x67, 0x48,
                          0x62, 0xDC, 0xB9, 0x50, 0xBC, 0x47, 0xCE, 0xD6};
  FpElemStr expected_k = {0x01, 0x01, 0x2D, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
                          0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9E,
                          0x0C, 0xDC, 0x65, 0xFB, 0x12, 0x99, 0x92, 0x1A,
                          0xF6, 0x2D, 0x53, 0x6C, 0xD1, 0x0B, 0x50, 0x0C};
  WriteFfElement(params.fp, sig_k, &actual_k, sizeof(actual_k));
  WriteFfElement(params.fp, sig_s, &actual_s, sizeof(actual_s));
  EXPECT_EQ(actual_k, expected_k);
  EXPECT_EQ(actual_s, expected_s);
}

TEST_F(EpidTpm2Test, SignProducesKnownSignatureUsingSha384Digest) {
  Epid20Params params;
  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  FfElementObj sig_k(&params.fp), sig_s(&params.fp);
  uint16_t counter = 0;

  OneTimePad my_prng;
  my_prng.InitUint8({
      // nonce randomized by commit
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
      0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9E, 0x0C, 0xDC, 0x65, 0xFB,
      0x12, 0x99, 0x92, 0x1A, 0xF6, 0x2D, 0x53, 0x6C, 0xD1, 0x0B, 0x50, 0x0C,
      // noncek randomized by sign
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x2D, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
      0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9E, 0x0C, 0xDC, 0x65, 0xFB,
      0x12, 0x99, 0x92, 0x1A, 0xF6, 0x2D, 0x53, 0x6C, 0xD1, 0x0B, 0x50, 0x0C,
  });
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&OneTimePad::Generate, &my_prng, &this->kMemberFValue,
                 epid2params);
  Tpm2Key* f_handle;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(tpm, kSha384, &this->kMemberFValue, &f_handle));
  THROW_ON_EPIDERR(Tpm2Commit(tpm, f_handle, nullptr, nullptr, 0, nullptr, k, l,
                              e, &counter));

  EXPECT_EQ(kEpidNoErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha384,
                     sizeof(this->kDigestSha384), counter, sig_k, sig_s));

  FpElemStr actual_s = {0};
  FpElemStr actual_k = {0};
  FpElemStr expected_s = {0xF6, 0x6E, 0xB9, 0x13, 0xF3, 0xBC, 0xBF, 0x67,
                          0x2D, 0x91, 0xF8, 0x5B, 0x0D, 0xC1, 0xE4, 0x1A,
                          0xA1, 0xD0, 0xFF, 0xC6, 0xA3, 0xCE, 0x03, 0x49,
                          0x9A, 0x80, 0x81, 0x1E, 0x19, 0x18, 0x46, 0x82};
  FpElemStr expected_k = {0x01, 0x01, 0x2D, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
                          0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9E,
                          0x0C, 0xDC, 0x65, 0xFB, 0x12, 0x99, 0x92, 0x1A,
                          0xF6, 0x2D, 0x53, 0x6C, 0xD1, 0x0B, 0x50, 0x0C};
  WriteFfElement(params.fp, sig_k, &actual_k, sizeof(actual_k));
  WriteFfElement(params.fp, sig_s, &actual_s, sizeof(actual_s));
  EXPECT_EQ(actual_k, expected_k);
  EXPECT_EQ(actual_s, expected_s);
}

TEST_F(EpidTpm2Test, SignProducesKnownSignatureUsingSha512Digest) {
  Epid20Params params;
  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  FfElementObj sig_k(&params.fp), sig_s(&params.fp);
  uint16_t counter = 0;

  OneTimePad my_prng;
  my_prng.InitUint8({
      // nonce randomized by commit
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
      0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9E, 0x0C, 0xDC, 0x65, 0xFB,
      0x12, 0x99, 0x92, 0x1A, 0xF6, 0x2D, 0x53, 0x6C, 0xD1, 0x0B, 0x50, 0x0C,
      // noncek randomized by sign
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x2D, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
      0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9E, 0x0C, 0xDC, 0x65, 0xFB,
      0x12, 0x99, 0x92, 0x1A, 0xF6, 0x2D, 0x53, 0x6C, 0xD1, 0x0B, 0x50, 0x0C,
  });
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&OneTimePad::Generate, &my_prng, &this->kMemberFValue,
                 epid2params);
  Tpm2Key* f_handle;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(tpm, kSha512, &this->kMemberFValue, &f_handle));
  THROW_ON_EPIDERR(Tpm2Commit(tpm, f_handle, nullptr, nullptr, 0, nullptr, k, l,
                              e, &counter));

  EXPECT_EQ(kEpidNoErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha512,
                     sizeof(this->kDigestSha512), counter, sig_k, sig_s));

  FpElemStr actual_s = {0};
  FpElemStr actual_k = {0};
  FpElemStr expected_s = {0xC1, 0xCA, 0x8B, 0x7C, 0x3A, 0x24, 0xDA, 0xD3,
                          0xD4, 0xBA, 0x1A, 0xEB, 0xE8, 0x76, 0x30, 0x34,
                          0x64, 0x4F, 0xFD, 0x1B, 0xB6, 0x82, 0xAD, 0x67,
                          0x35, 0x10, 0xFF, 0x9D, 0x86, 0x7E, 0xDE, 0x1C};
  FpElemStr expected_k = {0x01, 0x01, 0x2D, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
                          0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9E,
                          0x0C, 0xDC, 0x65, 0xFB, 0x12, 0x99, 0x92, 0x1A,
                          0xF6, 0x2D, 0x53, 0x6C, 0xD1, 0x0B, 0x50, 0x0C};
  WriteFfElement(params.fp, sig_k, &actual_k, sizeof(actual_k));
  WriteFfElement(params.fp, sig_s, &actual_s, sizeof(actual_s));
  EXPECT_EQ(actual_k, expected_k);
  EXPECT_EQ(actual_s, expected_s);
}

TEST_F(EpidTpm2Test, SignProducesKnownSignatureUsingSha512256Digest) {
  Epid20Params params;
  EcPointObj k(&params.G1), l(&params.G1), e(&params.G1);
  FfElementObj sig_k(&params.fp), sig_s(&params.fp);
  uint16_t counter = 0;

  OneTimePad my_prng;
  my_prng.InitUint8({
      // nonce randomized by commit
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
      0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9E, 0x0C, 0xDC, 0x65, 0xFB,
      0x12, 0x99, 0x92, 0x1A, 0xF6, 0x2D, 0x53, 0x6C, 0xD1, 0x0B, 0x50, 0x0C,
      // noncek randomized by sign
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x2D, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
      0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9E, 0x0C, 0xDC, 0x65, 0xFB,
      0x12, 0x99, 0x92, 0x1A, 0xF6, 0x2D, 0x53, 0x6C, 0xD1, 0x0B, 0x50, 0x0C,
  });
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tpm(&OneTimePad::Generate, &my_prng, &this->kMemberFValue,
                 epid2params);
  Tpm2Key* f_handle;
  THROW_ON_EPIDERR(
      Tpm2LoadExternal(tpm, kSha512_256, &this->kMemberFValue, &f_handle));
  THROW_ON_EPIDERR(Tpm2Commit(tpm, f_handle, nullptr, nullptr, 0, nullptr, k, l,
                              e, &counter));

  EXPECT_EQ(kEpidNoErr,
            Tpm2Sign(tpm, f_handle, this->kDigestSha256,
                     sizeof(this->kDigestSha256), counter, sig_k, sig_s));

  FpElemStr actual_s = {0};
  FpElemStr actual_k = {0};
  FpElemStr expected_s = {0x48, 0x48, 0xD5, 0x4C, 0x0A, 0x4F, 0x54, 0x47,
                          0x0D, 0xCA, 0x9F, 0xE0, 0x78, 0xCF, 0xF7, 0x69,
                          0x55, 0xFC, 0xCD, 0x8B, 0xEB, 0x63, 0x4B, 0x80,
                          0x20, 0xC8, 0x78, 0x80, 0xF8, 0xC2, 0xD4, 0xFB};
  FpElemStr expected_k = {0x01, 0x01, 0x2D, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
                          0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9E,
                          0x0C, 0xDC, 0x65, 0xFB, 0x12, 0x99, 0x92, 0x1A,
                          0xF6, 0x2D, 0x53, 0x6C, 0xD1, 0x0B, 0x50, 0x0C};
  WriteFfElement(params.fp, sig_k, &actual_k, sizeof(actual_k));
  WriteFfElement(params.fp, sig_s, &actual_s, sizeof(actual_s));
  EXPECT_EQ(actual_k, expected_k);
  EXPECT_EQ(actual_s, expected_s);
}

}  // namespace