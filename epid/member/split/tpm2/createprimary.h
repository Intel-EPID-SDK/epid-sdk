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
/// TPM2_CreatePrimary command interface.
/*! \file */
#ifndef EPID_MEMBER_SPLIT_TPM2_CREATEPRIMARY_H_
#define EPID_MEMBER_SPLIT_TPM2_CREATEPRIMARY_H_

#include "epid/common/errors.h"
#include "epid/common/types.h"  // HashAlg

/// \cond
typedef struct Tpm2Ctx Tpm2Ctx;
typedef struct Tpm2Key Tpm2Key;
/// \endcond

/// Creates Primary key
/*!

  When the key is no longer needed it can be freed using
  ::Tpm2FlushContext.

  \param[in,out] ctx
  TPM context.
  \param[in] hash_alg
  The hash algorithm to use.
  \param[out] key
  The generated TPM key.

  \returns ::EpidStatus

  \see Tpm2FlushContext
*/
EpidStatus Tpm2CreatePrimary(Tpm2Ctx* ctx, HashAlg hash_alg, Tpm2Key** key);

#endif  // EPID_MEMBER_SPLIT_TPM2_CREATEPRIMARY_H_
