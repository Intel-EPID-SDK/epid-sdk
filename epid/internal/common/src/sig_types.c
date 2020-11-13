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
/// Signature type detection implementation.
/*! \file */
#include "common/sig_types.h"
#include "common/endian_convert.h"
#include "epid/types.h"

size_t EpidGetSignatureRlCount(EpidNonSplitSignature const* sig) {
  if (!sig)
    return 0;
  else
    return ntohl(sig->n2);
}

size_t EpidGetSplitSignatureRlCount(EpidSplitSignature const* sig) {
  if (!sig)
    return 0;
  else
    return ntohl(sig->n2);
}

/// Infer type of a signature from its content
EpidSigType EpidDetectSigType(void const* sig_data, size_t sig_len) {
  // size of basic sig plus add-on fields (n2, rl_ver, etc.)
  const size_t non_split_sig_len =
      sizeof(EpidNonSplitSignature) - sizeof(NrProof);
  const size_t split_sig_len =
      sizeof(EpidSplitSignature) - sizeof(SplitNrProof);

  // only look at things big enough to be split sigs
  if (sig_len >= split_sig_len) {
    EpidSplitSignature* sig = (EpidSplitSignature*)sig_data;

    // check that the value we assumed was n2 results in a signature
    // of the size we have
    if ((EpidGetSplitSignatureRlCount(sig) * sizeof(SplitNrProof)) +
            split_sig_len ==
        sig_len) {
      return kSigSplit;
    }
  }

  // only look at things big enough to be non-split sigs
  if (sig_len >= non_split_sig_len) {
    EpidSignature* sig = (EpidSignature*)sig_data;

    // check that the value we assumed was n2 results in a signature
    // of the size we have
    if ((EpidGetSignatureRlCount((EpidNonSplitSignature*)sig) *
         sizeof(NrProof)) +
            non_split_sig_len ==
        sig_len) {
      return kSigNonSplit;
    }
  }

  // No signature type match
  return kSigUnknown;
}
