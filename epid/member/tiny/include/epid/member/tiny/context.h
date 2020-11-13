/*############################################################################
  # Copyright 2017-2020 Intel Corporation
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
/// Member context interface.
/*! \file */
#ifndef EPID_MEMBER_TINY_SRC_CONTEXT_H_
#define EPID_MEMBER_TINY_SRC_CONTEXT_H_
#include "epid/bitsupplier.h"
#include "epid/member/tiny/allowed_basenames.h"
#include "epid/member/tiny/native_types.h"
#include "epid/member/tiny/stack.h"
#include "epid/types.h"
#include "tinymath/mathtypes.h"

/// Size of SigRl with zero entries
#define MIN_SIGRL_SIZE (sizeof(SigRl) - sizeof(SigRlEntry))

/// Member context definition
typedef struct MemberCtx {
  GroupPubKey pub_key;              ///< group public key
  HashAlg hash_alg;                 ///< Hash algorithm to use
  MembershipCredential credential;  ///< Membership credential
  FpElem f;                         ///< secret f value
  NativeMemberPrecomp precomp;      ///< Precomputed pairing values
  PairingState pairing_state;       ///< pairing state
  int f_is_set;                     ///< f initialized
  int is_provisioned;    ///< member fully provisioned with key material
  BitSupplier rnd_func;  ///< Pseudo random number generation function
  Stack presigs;         ///< Container of pre-computed signature
  void* rnd_param;       ///< Pointer to user context for rnd_func
  AllowedBasenames* allowed_basenames;  ///< Allowed basenames
  SigRl* sig_rl;             ///< Pointer to Signature based revocation list
  size_t max_sigrl_entries;  ///< Maximum number of possible entries in SigRl
                             /// copied by value
  size_t max_allowed_basenames;  ///< Maximum number of allowed base names
  size_t max_precomp_sig;        ///< Maximum number of precomputed signatures
  unsigned char heap[1];         ///< Bulk storage space (flexible array)
} MemberCtx;

#endif  // EPID_MEMBER_TINY_SRC_CONTEXT_H_
