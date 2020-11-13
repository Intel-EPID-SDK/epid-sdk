/*############################################################################
# Copyright 2016-2019 Intel Corporation
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
 * \brief SHA256 implementation.
 */
#include <ippcp.h>
#include "ippmath/hash.h"
#include "bignum-internal.h"

EpidStatus Sha256MessageDigest(void const* msg, size_t len,
                               Sha256Digest* digest) {
  IppStatus sts;
  int ipp_len = (int)len;

  if (len && !msg) {
    return kEpidBadArgErr;
  }
  if (!digest) {
    return kEpidBadArgErr;
  }
  if (INT_MAX < len) {
    return kEpidBadArgErr;
  }

  sts = ippsSHA256MessageDigest(msg, ipp_len, (IppOctStr)digest);
  if (ippStsNoErr != sts) {
    if (ippStsLengthErr == sts) {
      return kEpidBadArgErr;
    } else {
      return kEpidMathErr;
    }
  }

  return kEpidNoErr;
}
