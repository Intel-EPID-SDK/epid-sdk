/*############################################################################
  # Copyright 2016-2019 Intel Corporation
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
#ifndef EPID_MEMBER_SPLIT_SRC_CONTEXT_H_
#define EPID_MEMBER_SPLIT_SRC_CONTEXT_H_
/*!
 * \file
 * \brief Member context interface.
 */

#include <epid/member/api.h>

#include <stddef.h>
#include "epid/bitsupplier.h"
#include "epid/errors.h"
#include "epid/stdtypes.h"
#include "epid/types.h"

/// \cond
typedef struct Tpm2Ctx Tpm2Ctx;
typedef struct Tpm2Key Tpm2Key;
typedef struct Epid2Params_ Epid2Params_;
typedef struct AllowedBasenames AllowedBasenames;
typedef struct Stack Stack;
typedef struct EcPoint EcPoint;
typedef struct FfElement FfElement;
/// \endcond

/// Member context definition
struct MemberCtx {
  Epid2Params_* epid2_params;  ///< Intel(R) EPID 2.0 params
  Tpm2Ctx* tpm2_ctx;           ///< TPM2 context
  GroupPubKey pub_key;         ///< group public key
  MemberPrecomp precomp;       ///< Member pre-computed data
  BitSupplier rnd_func;        ///< Pseudo random number generation function
  void* rnd_param;             ///< Pointer to user context for rnd_func
  SigRl const* sig_rl;         ///< Signature based revocation list - not owned
  AllowedBasenames* allowed_basenames;  ///< Base name list
  MembershipCredential credential;      ///< Membership credential
  Tpm2Key* f_handle;      ///< Handle to private f used for signing
  bool precomp_ready;     ///< provisioned precomputed value is ready for use
  bool is_provisioned;    ///< member fully provisioned with key material
  FpElemStr* external_f;  ///< f to use instead of EPS based f
  EcPoint const* h1;      ///< Group public key h1 value
  EcPoint const* h2;      ///< Group group public key h2 value
  EcPoint const* A;       ///< Membership Credential A value
  FfElement const* x;     ///< Membership Credential x value
  EcPoint const* w;       ///< Group group public key w value
  FfElement const* e12;   ///< an element in GT, = pairing (h1, g2)
  FfElement const* e22;   ///< an element in GT, = pairing (h2, g2)
  FfElement const* e2w;   ///< an element in GT, = pairing (h2, w)
  FfElement const* ea2;   ///< an element in GT, = pairing (g1, g2)
  Stack* presigs;         ///< Pre-computed signature pool
};

/// Pre-computed signature.
/*!
 Serialized form of an intermediate signature that does not depend on
 basename or message. This can be used to time-shift compute time needed to
 sign a message.
 */
#pragma pack(1)
typedef struct PreComputedSignature {
  G1ElemStr B;         ///< an element in G1
  G1ElemStr K;         ///< an element in G1
  G1ElemStr T;         ///< an element in G1
  G1ElemStr R1;        ///< an element in G1
  GtElemStr R2;        ///< an element in G1
  FpElemStr a;         ///< an integer between [0, p-1]
  FpElemStr b;         ///< an integer between [0, p-1]
  FpElemStr rx;        ///< an integer between [0, p-1]
  uint16_t rf_ctr;     ///< a TPM commit counter for rf
  bool is_rf_ctr_set;  ///< a flag to test if rf_ctr is set
  FpElemStr ra;        ///< an integer between [0, p-1]
  FpElemStr rb;        ///< an integer between [0, p-1]
  BigNumStr rnd_bsn;   ///< random basename
} PreComputedSignature;
#pragma pack()

/// Creates a handle to a private key given hash algoithm
EpidStatus CreatePrivateF(MemberCtx* ctx, HashAlg hash_alg, Tpm2Key** f_handle);

#endif  // EPID_MEMBER_SPLIT_SRC_CONTEXT_H_
