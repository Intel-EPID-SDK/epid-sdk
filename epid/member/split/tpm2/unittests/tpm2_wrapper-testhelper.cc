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
/// Tpm2Ctx wrapper class implementation.
/*! \file */
#include "tpm2_wrapper-testhelper.h"

#include <cstring>
#include <string>
#include <stdexcept>

#include "testhelper/epid2params_wrapper-testhelper.h"
#include "testhelper/epid_params-testhelper.h"
#include "testhelper/mem_params-testhelper.h"

#include "epid/member/api.h"
extern "C" {
#include "common/epid2params.h"
#include "epid/member/split/tpm2/context.h"
#include "epid/member/split/tpm2/sign.h"
#include "epid/types.h"
}

Tpm2CtxObj::Tpm2CtxObj(BitSupplier rnd_func, void* rnd_param,
                       const FpElemStr* f, Epid2ParamsObj const& params)
    : ctx_(nullptr) {
  EpidStatus sts = kEpidNoErr;
  BitSupplier rnd_func_ = NULL;
  void* rnd_param_ = NULL;
  MemberParams mem_params = {0};
  SetMemberParams(rnd_func, rnd_param, f, &mem_params);

  sts = Tpm2CreateContext(&mem_params, params, &rnd_func_, &rnd_param_, &ctx_);
  if (kEpidNoErr != sts) {
    printf("%s(%d): %s\n", __FILE__, __LINE__, "test defect:");
    throw std::logic_error(std::string("Failed to call: ") +
                           "Tpm2CreateContext()");
  }
}

Tpm2CtxObj::~Tpm2CtxObj() { Tpm2DeleteContext(&ctx_); }

Tpm2Ctx* Tpm2CtxObj::ctx() const { return ctx_; }

Tpm2CtxObj::operator Tpm2Ctx*() const { return ctx_; }

Tpm2CtxObj::operator const Tpm2Ctx*() const { return ctx_; }
