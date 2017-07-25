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
/// TPM key decompression APIs
/*! \file */

#ifndef EPID_MEMBER_TPM_DECOMPRESS_H_
#define EPID_MEMBER_TPM_DECOMPRESS_H_

#include "epid/common/errors.h"

/// \cond
typedef struct TpmCtx TpmCtx;
typedef struct G1ElemStr G1ElemStr;
typedef struct G2ElemStr G2ElemStr;
typedef struct FpElemStr FpElemStr;
typedef struct FqElemStr FqElemStr;
/// \endcond

/*!
  \addtogroup TpmModule tpm
  \ingroup EpidMemberModule
  @{
*/

/// Decompresses provisioned key
/*!

  If you provision a compressed key using ::TpmProvisionCompressed,
  you must call ::TpmDecompressKey before performing any other
  operations that use the TPM context.  Once decompressed, the context
  will maintain the decompressed key for the lifetime of the context.

  \note
  If the compressed private key has not been provisioned, the result
  of the decompression is undefined.

  \param[in,out] ctx
  The TPM context.

  \param[in] h1_str
  The h1 value of the group public key.

  \param[in] w_str
  The w value of the group public key.

  \param[in] Ax_str
  The Ax value of the compressed member private key.

  \param[out] A_str
  The A value of the member private key.

  \param[out] x_str
  The x value of the member private key.

  \returns ::EpidStatus

  \see TpmCreate
  \see TpmProvisionCompressed
 */
EpidStatus TpmDecompressKey(TpmCtx* ctx, G1ElemStr const* h1_str,
                            G2ElemStr const* w_str, FqElemStr const* Ax_str,
                            G1ElemStr* A_str, FpElemStr* x_str);

/*! @} */
#endif  // EPID_MEMBER_TPM_DECOMPRESS_H_
