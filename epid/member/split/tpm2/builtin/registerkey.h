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
/// RegisterKey Interface
/*! \file */

#ifndef EPID_MEMBER_SPLIT_TPM2_BUILTIN_REGISTERKEY_H_
#define EPID_MEMBER_SPLIT_TPM2_BUILTIN_REGISTERKEY_H_

#include "epid/common/errors.h"

/// \cond
typedef struct Tpm2Ctx Tpm2Ctx;
typedef struct Tpm2Key Tpm2Key;
/// \endcond

/// Registers key in internal context
/*!

  This function is used to register a key to be destroyed by the
  associated TPM2Ctx.

  \warning The result of registering the same key a second time is
  undefined.

  \param[in,out] ctx
  TPM context.
  \param[out] key
  The TPM key to register.

  \returns ::EpidStatus
*/
EpidStatus Tpm2RegisterKey(Tpm2Ctx* ctx, Tpm2Key* key);

#endif  // EPID_MEMBER_SPLIT_TPM2_BUILTIN_REGISTERKEY_H_
