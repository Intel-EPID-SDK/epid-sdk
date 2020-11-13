/*############################################################################
  # Copyright 2018-2019 Intel Corporation
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
/// Member configuration management implementation
/*! \file */

/// Indicate the functions should be exported
#define EXPORT_EPID_APIS
#include "epid/member/api.h"

/// Mark variables as unused
#define UNUSED(x) (void)(x)

EpidStatus EPID_MEMBER_API EpidMemberSetEntropyGenerator(BitSupplier rnd_func,
                                                         void* rnd_param,
                                                         MemberParams* config) {
  UNUSED(rnd_func);
  UNUSED(rnd_param);
  UNUSED(config);
  return kEpidOperationNotSupportedErr;
}

EpidStatus EPID_MEMBER_API EpidMemberSetPrivateF(FpElemStr const* f,
                                                 MemberParams* config) {
  if (!config) return kEpidBadConfigErr;
  config->f = f;
  return kEpidNoErr;
}

EpidStatus EPID_MEMBER_API EpidMemberSetMaxSigRlEntries(size_t n,
                                                        MemberParams* config) {
  UNUSED(n);
  UNUSED(config);
  return kEpidOperationNotSupportedErr;
}

EpidStatus EPID_MEMBER_API
EpidMemberSetMaxAllowedBasenames(size_t n, MemberParams* config) {
  UNUSED(n);
  UNUSED(config);
  return kEpidOperationNotSupportedErr;
}

EpidStatus EPID_MEMBER_API
EpidMemberSetMaxPrecomputedSigs(size_t n, MemberParams* config) {
  UNUSED(n);
  UNUSED(config);
  return kEpidOperationNotSupportedErr;
}
