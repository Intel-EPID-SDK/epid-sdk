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
/// Tpm2KeyHashAlg command interface.
/*! \file */
#ifndef EPID_MEMBER_SPLIT_TPM2_KEYINFO_H_
#define EPID_MEMBER_SPLIT_TPM2_KEYINFO_H_

#include "epid/common/types.h"  // HashAlg

/// \cond
typedef struct Tpm2Key Tpm2Key;
/// \endcond

/// Returns the hash algorithm associated with a key
/*!

  \param[in] key
  The TPM key handle.

  \returns The hash algorithm associated with the key

*/
HashAlg Tpm2KeyHashAlg(Tpm2Key const* key);

#endif  // EPID_MEMBER_SPLIT_TPM2_KEYINFO_H_
