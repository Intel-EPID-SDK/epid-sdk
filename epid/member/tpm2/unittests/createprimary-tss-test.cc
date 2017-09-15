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
/// TPM2_CreatePrimary unit tests.
/*! \file */

#include "epid/common-testhelper/epid_gtest-testhelper.h"
#include "gtest/gtest.h"

#include "epid/common-testhelper/epid2params_wrapper-testhelper.h"
#include "epid/common-testhelper/errors-testhelper.h"
#include "epid/member/tpm2/unittests/tpm2-testhelper.h"

extern "C" {
#include "epid/common/math/ecgroup.h"
#include "epid/common/src/epid2params.h"
#include "epid/member/tpm2/context.h"
#include "epid/member/tpm2/createprimary.h"
#include "epid/member/tpm2/ibm_tss/state.h"
}
namespace {

TEST_F(EpidTpm2Test, CreatePrimaryOnTssFailsGivenNullParameters) {
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tss(nullptr, nullptr, nullptr, epid2params);
  G1ElemStr res = {0};
  THROW_ON_EPIDERR(Tpm2SetHashAlg(tss, kSha256));
  EXPECT_EQ(kEpidBadArgErr, Tpm2CreatePrimary(tss, nullptr));
  EXPECT_EQ(kEpidBadArgErr, Tpm2CreatePrimary(nullptr, &res));
}
TEST_F(EpidTpm2Test, DISABLED_CreatePrimaryOnTssWorks) {
  Epid2ParamsObj epid2params;
  Tpm2CtxObj tss(nullptr, nullptr, nullptr, epid2params);
  G1ElemStr res = {0};
  THROW_ON_EPIDERR(Tpm2SetHashAlg(tss, kSha256));
  EXPECT_EQ(kEpidNoErr, Tpm2CreatePrimary(tss, &res));
  G1ElemStr expected = {
      // public x
      0x42, 0xd6, 0xff, 0xae, 0xd2, 0x4b, 0xda, 0x8d, 0xce, 0x78, 0x57, 0xd6,
      0xf2, 0x19, 0xa6, 0x2d, 0x04, 0x0c, 0xc6, 0xcc, 0x2d, 0x76, 0xde, 0x27,
      0x2f, 0x52, 0x59, 0xfb, 0xf3, 0x35, 0x0a, 0xc6,

      // public y
      0x38, 0x71, 0x6c, 0x16, 0x6a, 0xea, 0x0e, 0xc8, 0x7e, 0x3d, 0x62, 0x79,
      0xc2, 0xf8, 0xe5, 0x2e, 0xf1, 0x76, 0x89, 0x05, 0xe7, 0x76, 0xd6, 0x6f,
      0x44, 0xc4, 0x36, 0x2a, 0x40, 0xb1, 0x14, 0x64,
  };
  Tpm2Ctx* tmp = tss;
  EcPoint* point = NULL;
  THROW_ON_EPIDERR(NewEcPoint(tmp->epid2_params->G1, &point));
  EXPECT_EQ(kEpidNoErr,
            ReadEcPoint(tmp->epid2_params->G1, &res, sizeof(res), point));
  DeleteEcPoint(&point);
  EXPECT_EQ(expected, res);
}

}  // namespace
