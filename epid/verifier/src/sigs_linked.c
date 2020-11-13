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
 * \brief AreSigsLinked implementation.
 */
#define EXPORT_EPID_APIS
#include <epid/verifier.h>

#include <string.h>

// implements section 4.3 "Signature Linking" from Intel(R) EPID 2.0 Spec
bool EPID_VERIFIER_API EpidAreSigsLinked(EpidSignature const* sig1,
                                         size_t sig1_len,
                                         EpidSignature const* sig2,
                                         size_t sig2_len) {
  BasicSignature* sig1_ = (BasicSignature*)sig1;
  BasicSignature* sig2_ = (BasicSignature*)sig2;
  if (sig1_len < sizeof(BasicSignature) || sig2_len < sizeof(BasicSignature))
    return false;

  // Step 1. If B1 = B2 and K1 = K2, output true, otherwise output false.
  return (sig1_ && sig2_ &&
          0 == memcmp(&sig1_->B, &sig2_->B, sizeof(sig2_->B)) &&
          0 == memcmp(&sig1_->K, &sig2_->K, sizeof(sig2_->K)));
}
