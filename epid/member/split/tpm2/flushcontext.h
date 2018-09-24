/*############################################################################
  # Copyright 2018 Intel Corporation
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
/// SDK TPM FlushContext API.
/*! \file */

#ifndef EPID_MEMBER_SPLIT_TPM2_FLUSHCONTEXT_H_
#define EPID_MEMBER_SPLIT_TPM2_FLUSHCONTEXT_H_

#include "epid/common/errors.h"

/// \cond
typedef struct Tpm2Ctx Tpm2Ctx;
typedef struct Tpm2Key Tpm2Key;
/// \endcond

/*!
 \addtogroup Tpm2Module tpm2
 \ingroup EpidMemberModule
 @{
*/

/// Invokes TPM2_FlushContext command
/*!

  This command causes all context associated with a key to be removed
  from TPM memory, invalidating the key.

 \param[in,out] ctx
 TPM context.

 \param[in,out] key
 The Tpm2 key to flush.

 \returns ::EpidStatus
*/
EpidStatus Tpm2FlushContext(Tpm2Ctx* ctx, Tpm2Key** key);

/*! @} */

#endif  // EPID_MEMBER_SPLIT_TPM2_FLUSHCONTEXT_H_
