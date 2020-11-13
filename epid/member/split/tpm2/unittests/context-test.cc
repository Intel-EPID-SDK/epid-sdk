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
/// TPM Context unit tests.
/*! \file */
#include "epid/member/api.h"
#include "tpm2-testhelper.h"
#include "gtest/gtest.h"
#include "testhelper/epid2params_wrapper-testhelper.h"
#include "testhelper/epid_gtest-testhelper.h"
#include "testhelper/errors-testhelper.h"
#include "testhelper/mem_params-testhelper.h"
#include "testhelper/prng-testhelper.h"

extern "C" {
#include "common/epid2params.h"
#include "epid/member/split/tpm2/context.h"
#include "epid/member/split/tpm2/load_external.h"
}

namespace {
//////////////////////////////////////////////////////////////////////////
// Tpm2CreateContext Tests
TEST_F(EpidTpm2Test, CreateFailsGivenNullParameters) {
  Tpm2Ctx* ctx = nullptr;
  Prng my_prng;
  BitSupplier rnd_func = NULL;
  void* rnd_param = NULL;
  MemberParams mem_params = {0};
  Epid2ParamsObj epid_params;
  SetMemberParams(&Prng::Generate, &my_prng, nullptr, &mem_params);

  EXPECT_EQ(kEpidBadArgErr, Tpm2CreateContext(nullptr, epid_params, &rnd_func,
                                              &rnd_param, &ctx));
  EXPECT_EQ(kEpidBadArgErr, Tpm2CreateContext(&mem_params, nullptr, &rnd_func,
                                              &rnd_param, &ctx));
  EXPECT_EQ(kEpidBadArgErr, Tpm2CreateContext(&mem_params, epid_params, nullptr,
                                              &rnd_param, &ctx));
  EXPECT_EQ(kEpidBadArgErr, Tpm2CreateContext(&mem_params, epid_params,
                                              &rnd_func, nullptr, &ctx));
  EXPECT_EQ(kEpidBadArgErr, Tpm2CreateContext(&mem_params, epid_params,
                                              &rnd_func, &rnd_param, nullptr));
}

TEST_F(EpidTpm2Test, CreateSucceedsGivenValidParameters) {
  Tpm2Ctx* ctx = nullptr;
  Prng my_prng;
  BitSupplier rnd_func = NULL;
  void* rnd_param = NULL;
  MemberParams mem_params = {0};
  Epid2ParamsObj epid_params;
  SetMemberParams(&Prng::Generate, &my_prng, nullptr, &mem_params);

  EXPECT_EQ(kEpidNoErr, Tpm2CreateContext(&mem_params, epid_params, &rnd_func,
                                          &rnd_param, &ctx));
  Tpm2DeleteContext(&ctx);
}

//////////////////////////////////////////////////////////////////////////
// Tpm2DeleteContext Tests
TEST_F(EpidTpm2Test, DeleteWorksGivenNullTpm2Ctx) {
  Tpm2DeleteContext(nullptr);
  Tpm2Ctx* ctx = nullptr;
  Tpm2DeleteContext(&ctx);
}

TEST_F(EpidTpm2Test, DeleteNullsTpm2Ctx) {
  Tpm2Ctx* ctx = nullptr;
  Prng my_prng;
  BitSupplier rnd_func = NULL;
  void* rnd_param = NULL;
  MemberParams mem_params = {0};
  Epid2ParamsObj epid_params;
  SetMemberParams(&Prng::Generate, &my_prng, nullptr, &mem_params);
  Tpm2CreateContext(&mem_params, epid_params, &rnd_func, &rnd_param, &ctx);
  Tpm2DeleteContext(&ctx);
  EXPECT_EQ(nullptr, ctx);
}

TEST_F(EpidTpm2Test, PROTECTED_SampleTest) { SUCCEED(); }

TEST_F(EpidTpm2Test, PROTECTED_EPS1_SampleTest) { SUCCEED(); }

TEST_F(EpidTpm2Test, PROTECTED_EPSOther_SampleTest) { SUCCEED(); }

}  // namespace
