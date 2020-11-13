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
/// SDK TPM API.
/*! \file */

#ifndef EPID_MEMBER_SPLIT_TPM2_LOAD_EXTERNAL_H_
#define EPID_MEMBER_SPLIT_TPM2_LOAD_EXTERNAL_H_

#include "epid/errors.h"
#include "epid/types.h"  // HashAlg

/// \cond
typedef struct Tpm2Ctx Tpm2Ctx;
typedef struct Tpm2Key Tpm2Key;
typedef struct FpElemStr FpElemStr;
/// \endcond

/*!
 \addtogroup Tpm2Module tpm2
 \ingroup EpidMemberModule
 @{
*/

/// Invokes TPM2_LoadExternal command
/*!

  This command is used to load an object that is not a Protected
  Object into the TPM. The command allows loading of a public area or
  both a public and sensitive area.

  When the key is no longer needed it can be freed using
  ::Tpm2FlushContext.

  \param[in,out] ctx
  TPM context.
  \param[in] hash_alg
  The hash algorithm to use.
  \param[in] f_str
  The f value of the member private key.
  \param[out] key
  The generated TPM key.

  \returns ::EpidStatus

  \see Tpm2FlushContext
*/
EpidStatus Tpm2LoadExternal(Tpm2Ctx* ctx, HashAlg hash_alg,
                            FpElemStr const* f_str, Tpm2Key** key);

/*! @} */

#endif  // EPID_MEMBER_SPLIT_TPM2_LOAD_EXTERNAL_H_
