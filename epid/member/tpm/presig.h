/*############################################################################
  # Copyright 2017 Intel Corporation
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
/// Sensitive pre-computed signature APIs
/*! \file */

#ifndef EPID_MEMBER_TPM_PRESIG_H_
#define EPID_MEMBER_TPM_PRESIG_H_

#include <stddef.h>

#include "epid/common/errors.h"

/// \cond
typedef struct TpmCtx TpmCtx;
/// \endcond

/*!
  \addtogroup TpmModule tpm
  \ingroup EpidMemberModule
  @{
*/

/// Extends the TPM's pool of pre-computed signatures.
/*!

  \param[in,out] ctx
  The TPM context.

  \param[in] number_presigs
  The number of pre-computed signatures to add to the pool.

  \returns ::EpidStatus

  \see TpmGetNumPreSigs
 */
EpidStatus TpmAddPreSigs(TpmCtx* ctx, size_t number_presigs);

/// Gets the number of pre-computed signatures in the TPM's pool.
/*!

  \param[in,out] ctx
  The TPM context.

  \returns
  Number of pre-computed signatures in TPM's pool

  \see TpmAddPreSigs
 */
size_t TpmGetNumPreSigs(TpmCtx const* ctx);

/*! @} */
#endif  // EPID_MEMBER_TPM_PRESIG_H_
