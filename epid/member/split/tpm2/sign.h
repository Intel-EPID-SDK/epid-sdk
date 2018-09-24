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
/// SDK TPM Sign API.
/*! \file */

#ifndef EPID_MEMBER_SPLIT_TPM2_SIGN_H_
#define EPID_MEMBER_SPLIT_TPM2_SIGN_H_

#include <stddef.h>

#include "epid/common/errors.h"
#include "epid/common/stdtypes.h"

/// \cond
typedef struct Tpm2Ctx Tpm2Ctx;
typedef struct Tpm2Key Tpm2Key;
typedef struct FfElement FfElement;
/// \endcond

/*!
\addtogroup Tpm2Module tpm2
\ingroup EpidMemberModule
@{
*/

/// Performs TPM2_Sign TPM command.
/*!
Calculate a pair (k, s) an ECDAA signature.

\param[in] ctx
The TPM context.
\param[in] key
The private key to use for signing
\param[in] digest
Digest to be signed.
\param[in] digest_len
The size of digest in bytes.
\param[in] counter
A value associated with the random r generated during TPM2_Commit.
\param[out] k
The ECDAA signature k value. Nonce produced by the TPM during signing.
\param[out] s
The ECDAA signature s value.

\returns ::EpidStatus

\see Tpm2CreateContext
\see Tpm2Commit
*/
EpidStatus Tpm2Sign(Tpm2Ctx* ctx, Tpm2Key const* key, void const* digest,
                    size_t digest_len, uint16_t counter, FfElement* k,
                    FfElement* s);

/// Erases random r value associated with counter.
/*!

\param[in] ctx
The TPM context.
\param[in] counter
To be released value associated with the random r generated during TPM2_Commit.
\param[in] key
The private key used during TPM2_Commit.

\note
This function should be used if Tpm2Sign wasn't called after Tpm2Commit
which created counter.

\returns ::EpidStatus

\see Tpm2Commit
*/
EpidStatus Tpm2ReleaseCounter(Tpm2Ctx* ctx, uint16_t counter,
                              Tpm2Key const* key);

/*! @} */

#endif  // EPID_MEMBER_SPLIT_TPM2_SIGN_H_
