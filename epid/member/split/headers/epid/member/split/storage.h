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
/// Member credentials storage helper API
/*! \file */
#ifndef EPID_MEMBER_SPLIT_SRC_STORAGE_H_
#define EPID_MEMBER_SPLIT_SRC_STORAGE_H_

#include <stdint.h>
#include "epid/errors.h"

/// \cond
typedef struct Tpm2Ctx Tpm2Ctx;
typedef struct GroupPubKey GroupPubKey;
typedef struct MembershipCredential MembershipCredential;
/// \endcond

/// Write membership credential to TPM non-volatile memory.
/*!

Allocates TPM non volatile memory for membership credentials.  Writes
group public key and member private key parameters A and x into space
allocated.

\param[in] ctx
The TPM context.
\param[in] pub_key
Group public key.
\param[in] credential
Membership credential. NULL indicates clearing of existing credential.

\returns ::EpidStatus

\see EpidNvReadMembershipCredential
*/
EpidStatus EpidNvWriteMembershipCredential(
    Tpm2Ctx* ctx, GroupPubKey const* pub_key,
    MembershipCredential const* credential);

/// Read membership credential from TPM non-volatile memory.
/*!
\param[in] ctx
The TPM context.
\param[out] pub_key
Group public key.
\param[out] credential
Membership credential.

\returns ::EpidStatus

\see EpidNvWriteMembershipCredential
*/
EpidStatus EpidNvReadMembershipCredential(Tpm2Ctx* ctx, GroupPubKey* pub_key,
                                          MembershipCredential* credential);

/// Clear membership credential from TPM non-volatile memory.
/*!
\param[in] ctx
The TPM context.

\returns ::EpidStatus
*/
EpidStatus EpidNvClearMembershipCredential(Tpm2Ctx* ctx);
#endif  // EPID_MEMBER_SPLIT_SRC_STORAGE_H_
