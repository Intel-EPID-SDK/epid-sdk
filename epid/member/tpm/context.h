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
/// Sensitive member context APIs
/*! \file */

#ifndef EPID_MEMBER_TPM_CONTEXT_H_
#define EPID_MEMBER_TPM_CONTEXT_H_

#include "epid/common/errors.h"
#include "epid/common/bitsupplier.h"

/// \cond
typedef struct TpmCtx TpmCtx;
typedef struct FpElemStr FpElemStr;
typedef struct Epid2Params_ Epid2Params_;
typedef struct OctStr256 OctStr256;
/// \endcond

/*!
  \addtogroup TpmModule tpm
  \ingroup EpidMemberModule
  @{
*/

/// Creates a new Tpm context
/*!

  Must be called to create the TPM context that is used by other TPM
  APIs.

  ::TpmDelete must be called to safely release the TPM context.

  You need to use a cryptographically secure random number generator
  to create a TPM context using ::TpmCreate. The ::BitSupplier is
  provided as a function prototype for your own implementation of the
  random number generator.

  \param[in] rnd_func
  Random number generator.

  \param[in] rnd_param
  Pass through user data that will be passed to the user_data
  parameter of the random number generator.

  \param[in] epid2_params
  The field and group parameters.

  \param[out] ctx
  Newly constructed TPM context.

  \returns ::EpidStatus

  \see TpmDelete
  \see TpmProvision

 */
EpidStatus TpmCreate(BitSupplier rnd_func, void* rnd_param,
                     Epid2Params_ const* epid2_params, TpmCtx** ctx);

/// Deletes an existing Tpm context.
/*!

  Must be called to safely release a TPM context created using
  ::TpmCreate.

  De-initializes the context, frees memory used by the context, and
  sets the context pointer to NULL.

  \param[in,out] ctx
  The TPM context. Can be NULL.

  \see TpmCreate
 */
void TpmDelete(TpmCtx** ctx);

/// Provisions Tpm with sensitive parameters
/*!

  \param[in,out] ctx
  The TPM context.

  \param f_str
  The f value of the member private key.

  \returns ::EpidStatus

  \see TpmCreate
  \see TpmInit

 */
EpidStatus TpmProvision(TpmCtx* ctx, FpElemStr const* f_str);

/// Provisions Tpm with compressed key seed
/*!

  You must call ::TpmDecompressKey before performing any other
  operations that use the TPM context.

  \param[in,out] ctx
  The TPM context.

  \param[in] seed
  The seed value of the compressed key.

  \returns ::EpidStatus

  \see TpmCreate
  \see TpmInit
  \see TpmDecompressKey

 */
EpidStatus TpmProvisionCompressed(TpmCtx* ctx, OctStr256 const* seed);

/*! @} */

#endif  // EPID_MEMBER_TPM_CONTEXT_H_
