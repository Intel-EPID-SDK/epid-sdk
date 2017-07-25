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
#ifndef EPID_MEMBER_API_H_
#define EPID_MEMBER_API_H_

#include <stddef.h>
#include "epid/common/stdtypes.h"
#include "epid/common/types.h"
#include "epid/common/errors.h"
#include "epid/common/bitsupplier.h"

/*!
 * \file
 * \brief Intel(R) EPID SDK member API.
 */

/// Member functionality
/*!
  \defgroup EpidMemberModule member

  Defines the APIs needed by Intel(R) EPID members. Each member
  context (::MemberCtx) represents membership in a single group.

  To use this module, include the header epid/member/api.h.

  \ingroup EpidModule
  @{
*/

/// Internal context of member.
typedef struct MemberCtx MemberCtx;

/// Creates a new member context.
/*!
 Must be called to create the member context that is used by
 other "Member" APIs.

 Allocates memory for the context, then initializes it.

 EpidMemberDelete() must be called to safely release the member context.

 You need to use a cryptographically secure random
 number generator to create a member context using
 ::EpidMemberCreate. The ::BitSupplier is provided
 as a function prototype for your own implementation
 of the random number generator.

 \param[in] pub_key
 The group certificate.
 \param[in] priv_key
 The member private key.
 \param[in] precomp
 Optional pre-computed data. If NULL the value is computed internally and is
 readable using EpidMemberWritePrecomp().
 \param[in] rnd_func
 Random number generator.
 \param[in] rnd_param
 Pass through user data that will be passed to the user_data
 parameter of the random number generator.
 \param[out] ctx
 Newly constructed member context.

 \returns ::EpidStatus

 \warning
 For security rnd_func should be a cryptographically secure random
 number generator.

 \note
 If the result is not ::kEpidNoErr the content of ctx is undefined.

 \see EpidMemberDelete
 \see EpidMemberWritePrecomp
 \see BitSupplier

 \b Example

 \ref UserManual_GeneratingAnIntelEpidSignature
 */
EpidStatus EpidMemberCreate(GroupPubKey const* pub_key, PrivKey const* priv_key,
                            MemberPrecomp const* precomp, BitSupplier rnd_func,
                            void* rnd_param, MemberCtx** ctx);

/// Deletes an existing member context.
/*!
 Must be called to safely release a member context created using
 EpidMemberCreate().

 De-initializes the context, frees memory used by the context, and sets the
 context pointer to NULL.

 \param[in,out] ctx
 The member context. Can be NULL.

 \see EpidMemberCreate

 \b Example

 \ref UserManual_GeneratingAnIntelEpidSignature
 */
void EpidMemberDelete(MemberCtx** ctx);

/// Serializes the pre-computed member settings.
/*!
 \param[in] ctx
 The member context.
 \param[out] precomp
 The Serialized pre-computed member settings.

 \returns ::EpidStatus

 \note
 If the result is not ::kEpidNoErr, the content of precomp is undefined.

 \b Example

 \ref UserManual_GeneratingAnIntelEpidSignature
 */
EpidStatus EpidMemberWritePrecomp(MemberCtx const* ctx, MemberPrecomp* precomp);

/// Sets the hash algorithm to be used by a member.
/*!
 \param[in] ctx
 The member context.
 \param[in] hash_alg
 The hash algorithm to use.

 \returns ::EpidStatus

 \note
 If the result is not ::kEpidNoErr, the hash algorithm used by the member is
 undefined.

 \see EpidMemberCreate
 \see ::HashAlg

 \b Example

 \ref UserManual_GeneratingAnIntelEpidSignature
 */
EpidStatus EpidMemberSetHashAlg(MemberCtx* ctx, HashAlg hash_alg);

/// Sets the signature based revocation list to be used by a member.
/*!
 The caller is responsible for ensuring the revocation list is authorized,
 e.g. signed by the issuer. The caller is also responsible checking the version
 of the revocation list. The call fails if trying to set an older version
 of the revocation list than was last set.

 \attention
 The memory pointed to by sig_rl is accessed directly by the member
 until a new list is set or the member is destroyed. Do not modify the
 contents of this memory. The behavior of subsequent operations that rely on
 the revocation list is undefined if the memory is modified.

 \attention
 It is the responsibility of the caller to free the memory pointed to by sig_rl
 after the member is no longer using it.

 \param[in] ctx
 The member context.
 \param[in] sig_rl
 The signature based revocation list.
 \param[in] sig_rl_size
 The size of the signature based revocation list in bytes.

 \returns ::EpidStatus

 \note
 If the result is not ::kEpidNoErr the signature based revocation list pointed
 to by the member is not changed.

 \see EpidMemberCreate

 \b Example

 \ref UserManual_GeneratingAnIntelEpidSignature
 */
EpidStatus EpidMemberSetSigRl(MemberCtx* ctx, SigRl const* sig_rl,
                              size_t sig_rl_size);

/// Computes the size in bytes required for an Intel(R) EPID signature.
/*!
 \param[in] sig_rl
 The signature based revocation list that is used. NULL is treated as
 a zero length list.

 \returns
 Size in bytes of an Intel(R) EPID signature including proofs for each entry
 in the signature based revocation list.

 \see ::SigRl

 \b Example

 \ref UserManual_GeneratingAnIntelEpidSignature
*/
size_t EpidGetSigSize(SigRl const* sig_rl);

/// Writes an Intel(R) EPID signature.
/*!
 \param[in] ctx
 The member context.
 \param[in] msg
 The message to sign.
 \param[in] msg_len
 The length in bytes of message.
 \param[in] basename
 Optional basename. If basename is NULL a random basename is used.
 Signatures generated using random basenames are anonymous. Signatures
 generated using the same basename are linkable by the verifier. If a
 basename is provided, it must already be registered, or
 ::kEpidBadArgErr is returned.
 \param[in] basename_len
 The size of basename in bytes. Must be 0 if basename is NULL.
 \param[out] sig
 The generated signature
 \param[in] sig_len
 The size of signature in bytes. Must be equal to value returned by
 EpidGetSigSize().

 \returns ::EpidStatus

 \note
 If the result is not ::kEpidNoErr the content of sig is undefined.

 \see
 EpidMemberCreate
 \see
 EpidMemberSetHashAlg
 \see
 EpidMemberSetSigRl
 \see
 EpidGetSigSize

 \b Example

 \ref UserManual_GeneratingAnIntelEpidSignature
 */
EpidStatus EpidSign(MemberCtx const* ctx, void const* msg, size_t msg_len,
                    void const* basename, size_t basename_len,
                    EpidSignature* sig, size_t sig_len);

/// Registers a basename with a member.
/*!

 To prevent loss of privacy, the member keeps a list of basenames
 (corresponding to authorized verifiers). The member signs a message
 with a basename only if the basename is in the member's basename
 list.

 \warning
 The use of a name-based signature creates a platform unique
 pseudonymous identifier. Because it reduces the member's privacy, the
 user should be notified when it is used and should have control over
 its use.

 \param[in] ctx
 The member context.
 \param[in] basename
 The basename.
 \param[in] basename_len
 Length of the basename.

 \returns ::EpidStatus

 \retval ::kEpidDuplicateErr
 The basename was already registered.

 \note
 If the result is not ::kEpidNoErr or ::kEpidDuplicateErr it is undefined if the
 basename is registered.

 \b Example

 \ref UserManual_GeneratingAnIntelEpidSignature
 */
EpidStatus EpidRegisterBaseName(MemberCtx* ctx, void const* basename,
                                size_t basename_len);

/// Extends the member's pool of pre-computed signatures.
/*!
  Generate new pre-computed signatures and add them to the internal pool.

 \param[in] ctx
 The member context.
 \param[in] number_presigs
 The number of pre-computed signatures to add to the internal pool.

 \returns ::EpidStatus

 \see ::EpidMemberCreate
 */
EpidStatus EpidAddPreSigs(MemberCtx* ctx, size_t number_presigs);

/// Gets the number of pre-computed signatures in the member's pool.
/*!
 \param[in] ctx
 The member context.

 \returns
 Number of remaining pre-computed signatures. Returns 0 if ctx is NULL.

 \see ::EpidMemberCreate
*/
size_t EpidGetNumPreSigs(MemberCtx const* ctx);

/// Creates a request to join a group.
/*!
 The created request is part of the interaction with an issuer needed to join
 a group. This interaction with the issuer is outside the scope of this API.

 \param[in] pub_key
 The group certificate of group to join.
 \param[in] ni
 The nonce chosen by issuer as part of join protocol.
 \param[in] f
 A randomly selected integer in [1, p-1].
 \param[in] rnd_func
 Random number generator.
 \param[in] rnd_param
 Pass through context data for rnd_func.
 \param[in] hash_alg
 The hash algorithm to be used.
 \param[out] join_request
 The join request.

 \returns ::EpidStatus

 \warning
 For security rnd_func should be a cryptographically secure random
 number generator.

 \note
 The default hash algorithm in Member is SHA-512. This is the
 recommended option if you do not override the hash algorithm
 elsewhere.

 \note
 If the result is not ::kEpidNoErr, the content of join_request is undefined.

 \see ::HashAlg
 */
EpidStatus EpidRequestJoin(GroupPubKey const* pub_key, IssuerNonce const* ni,
                           FpElemStr const* f, BitSupplier rnd_func,
                           void* rnd_param, HashAlg hash_alg,
                           JoinRequest* join_request);

/// Creates a basic signature for use in constrained environment.
/*!
 Used in constrained environments where, due to limited memory, it may not
 be possible to process through a large and potentially unbounded revocation
 list.

 \param[in] ctx
 The member context.
 \param[in] msg
 The message.
 \param[in] msg_len
 The length of message in bytes.
 \param[in] basename
 Optional basename. If basename is NULL a random basename is used.
 Signatures generated using random basenames are anonymous. Signatures
 generated using the same basename are linkable by the verifier. If a
 basename is provided it must already be registered or
 ::kEpidBadArgErr is returned.
 \param[in] basename_len
 The size of basename in bytes. Must be 0 if basename is NULL.
 \param[out] sig
 The generated basic signature

 \returns ::EpidStatus

 \note
 This function should be used in conjunction with EpidNrProve()

 \note
 If the result is not ::kEpidNoErr the content of sig, is undefined.

 \see EpidMemberCreate
 \see EpidNrProve
 */
EpidStatus EpidSignBasic(MemberCtx const* ctx, void const* msg, size_t msg_len,
                         void const* basename, size_t basename_len,
                         BasicSignature* sig);

/// Calculates a non-revoked proof for a single signature based revocation
/// list entry.
/*!
 Used in constrained environments where, due to limited memory, it may not
 be possible to process through a large and potentially unbounded revocation
 list.

 \param[in] ctx
 The member context.
 \param[in] msg
 The message.
 \param[in] msg_len
 The length of message in bytes.
 \param[in] sig
 The basic signature.
 \param[in] sigrl_entry
 The signature based revocation list entry.
 \param[out] proof
 The generated non-revoked proof.

 \returns ::EpidStatus

 \note
 This function should be used in conjunction with EpidSignBasic().

 \note
 If the result is not ::kEpidNoErr, the content of proof is undefined.

 \see EpidMemberCreate
 \see EpidSignBasic
 */
EpidStatus EpidNrProve(MemberCtx const* ctx, void const* msg, size_t msg_len,
                       BasicSignature const* sig, SigRlEntry const* sigrl_entry,
                       NrProof* proof);

/// Assembles member private key from membership credential and f value.
/*!

  Combines membership credential obtained from the issuer in response
  to a successful join request with the f value chosen by the member
  to create a complete member private key.

  The assembled private key is sanity checked to confirm it is a
  possible key in the group.  If it is not ::kEpidBadArgErr is
  returned.

  \param[in] credential
  Membership credential received.
  \param[in] f
  The f value used to generate the join request associated with the
  membership credential.
  \param[in] pub_key
  The public key of the group.
  \param[out] priv_key
  The private key.

  \returns ::EpidStatus

  \see EpidRequestJoin
*/
EpidStatus EpidAssemblePrivKey(MembershipCredential const* credential,
                               FpElemStr const* f, GroupPubKey const* pub_key,
                               PrivKey* priv_key);

/// Decompresses compressed member private key.
/*!

  Converts a compressed member private key into a member
  private key for use by other member APIs.

  \param[in] pub_key
  The public key of the group.
  \param[in] compressed_privkey
  The compressed member private key to be decompressed.
  \param[out] priv_key
  The member private key.

  \returns ::EpidStatus

  \b Example

  \ref UserManual_GeneratingAnIntelEpidSignature
 */
EpidStatus EpidDecompressPrivKey(GroupPubKey const* pub_key,
                                 CompressedPrivKey const* compressed_privkey,
                                 PrivKey* priv_key);

/*! @} */
#endif  // EPID_MEMBER_API_H_
