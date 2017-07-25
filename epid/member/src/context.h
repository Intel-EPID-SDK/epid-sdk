/*############################################################################
  # Copyright 2016-2017 Intel Corporation
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
#ifndef EPID_MEMBER_SRC_CONTEXT_H_
#define EPID_MEMBER_SRC_CONTEXT_H_
/*!
 * \file
 * \brief Member context interface.
 */

#include <epid/member/api.h>

#include <stddef.h>

#include "epid/common/errors.h"
#include "epid/common/types.h"
#include "epid/common/bitsupplier.h"

/// \cond
typedef struct TpmCtx TpmCtx;
typedef struct Epid2Params_ Epid2Params_;
typedef struct AllowedBasenames AllowedBasenames;
/// \endcond

/// Member context definition
struct MemberCtx {
  Epid2Params_* epid2_params;  ///< Intel(R) EPID 2.0 params
  TpmCtx* tpm_ctx;             ///< TPM context
  GroupPubKey pub_key;         ///< group public key
  MemberPrecomp precomp;       ///< Member pre-computed data
  BitSupplier rnd_func;        ///< Pseudo random number generation function
  void* rnd_param;             ///< Pointer to user context for rnd_func
  SigRl const* sig_rl;         ///< Signature based revocation list - not owned
  AllowedBasenames* allowed_basenames;  ///< Base name list
  HashAlg hash_alg;                     ///< Hash algorithm to use
};

#endif  // EPID_MEMBER_SRC_CONTEXT_H_
