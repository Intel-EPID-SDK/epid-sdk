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
  ############################################################################*/
/// Tpm2LoadExternal unit tests.
/*! \file */

#include <stdint.h>
#include "tpm2-testhelper.h"
#include "gtest/gtest.h"
#include "testhelper/epid2params_wrapper-testhelper.h"
#include "testhelper/errors-testhelper.h"
#include "testhelper/prng-testhelper.h"

extern "C" {
#include "epid/member/split/tpm2/load_external.h"
}

namespace {
TEST_F(EpidTpm2Test, SetHashAlgFailsIfHashAlgNotSupported) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  FpElemStr f_str = this->kMemberFValue;
  Tpm2CtxObj ctx(&Prng::Generate, &my_prng, &f_str, epid2params);
  Tpm2Key* f_handle;
  EXPECT_EQ(kEpidHashAlgorithmNotSupported,
            Tpm2LoadExternal(ctx, kSha3_256, &f_str, &f_handle));

  EXPECT_EQ(kEpidHashAlgorithmNotSupported,
            Tpm2LoadExternal(ctx, kSha3_384, &f_str, &f_handle));

  EXPECT_EQ(kEpidHashAlgorithmNotSupported,
            Tpm2LoadExternal(ctx, kSha3_512, &f_str, &f_handle));
}
//////////////////////////////////////////////////////////////////////////
// Tpm2LoadExternal Tests
TEST_F(EpidTpm2Test, LoadExternalFailsGivenNullParameters) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  FpElemStr f_str = this->kMemberFValue;
  Tpm2CtxObj ctx(&Prng::Generate, &my_prng, &f_str, epid2params);
  Tpm2Key* f_handle;
  EXPECT_EQ(kEpidBadArgErr,
            Tpm2LoadExternal(nullptr, kSha256, &f_str, &f_handle));
  EXPECT_EQ(kEpidBadArgErr, Tpm2LoadExternal(ctx, kSha256, nullptr, &f_handle));
}
TEST_F(EpidTpm2Test, LoadExternalCanLoadFValueSha256) {
  Prng my_prng;
  Epid2ParamsObj epid2params;
  FpElemStr f_str = this->kMemberFValue;
  Tpm2CtxObj ctx(&Prng::Generate, &my_prng, &f_str, epid2params);
  Tpm2Key* f_handle;
  EXPECT_EQ(kEpidNoErr, Tpm2LoadExternal(ctx, kSha256, &f_str, &f_handle));
}
}  // namespace
