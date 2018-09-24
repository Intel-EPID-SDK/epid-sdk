/*############################################################################
  # Copyright 2016-2018 Intel Corporation
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

/*!
 * \file
 * \brief EpidGetSigSize implementation.
 */
#define EXPORT_EPID_APIS
#include "epid/common/src/endian_convert.h"
#include "epid/common/src/sig_types.h"
#include "epid/member/api.h"

size_t EPID_MEMBER_API EpidGetSigSize(SigRl const* sig_rl) {
  const size_t kMinSigSize = sizeof(EpidSplitSignature) - sizeof(SplitNrProof);
  if (!sig_rl) {
    return kMinSigSize;
  } else {
    if (ntohl(sig_rl->n2) > (SIZE_MAX - kMinSigSize) / sizeof(SplitNrProof)) {
      return kMinSigSize;
    } else {
      return kMinSigSize + ntohl(sig_rl->n2) * sizeof(SplitNrProof);
    }
  }
}
