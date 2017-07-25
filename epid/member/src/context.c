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

/*!
 * \file
 * \brief Member context implementation.
 */

#include <epid/member/api.h>

#include <string.h>

#include "epid/member/tpm/context.h"
#include "epid/member/tpm/init.h"
#include "epid/member/src/context.h"
#include "epid/common/src/memory.h"
#include "epid/common/src/endian_convert.h"
#include "epid/common/src/sigrlvalid.h"
#include "epid/common/src/epid2params.h"
#include "epid/member/tpm/presig.h"
#include "epid/member/src/precomp.h"
#include "epid/member/src/allowed_basenames.h"

/// Handle SDK Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus EpidMemberCreate(GroupPubKey const* pub_key, PrivKey const* priv_key,
                            MemberPrecomp const* precomp, BitSupplier rnd_func,
                            void* rnd_param, MemberCtx** ctx) {
  EpidStatus sts = kEpidErr;
  MemberCtx* member_ctx = NULL;

  if (!pub_key || !priv_key || !rnd_func || !ctx) {
    return kEpidBadArgErr;
  }

  // The member verifies that gid in public key and in private key
  // match. If mismatch, abort and return operation failed.
  if (memcmp(&pub_key->gid, &priv_key->gid, sizeof(GroupId))) {
    return kEpidBadArgErr;
  }

  // Allocate memory for MemberCtx
  member_ctx = SAFE_ALLOC(sizeof(MemberCtx));
  if (!member_ctx) {
    return kEpidMemAllocErr;
  }

  do {
    // set the default hash algorithm to sha512
    member_ctx->hash_alg = kSha512;
    member_ctx->rnd_func = rnd_func;
    member_ctx->rnd_param = rnd_param;
    member_ctx->pub_key = *pub_key;
    member_ctx->sig_rl = NULL;

    sts = CreateBasenames(&member_ctx->allowed_basenames);
    BREAK_ON_EPID_ERROR(sts);
    // Internal representation of Epid2Params
    sts = CreateEpid2Params(&member_ctx->epid2_params);
    BREAK_ON_EPID_ERROR(sts);

    // create and minimally provision TPM
    sts = TpmCreate(rnd_func, rnd_param, member_ctx->epid2_params,
                    &member_ctx->tpm_ctx);
    BREAK_ON_EPID_ERROR(sts);

    sts = TpmProvision(member_ctx->tpm_ctx, &priv_key->f);
    BREAK_ON_EPID_ERROR(sts);

    // pre-computation
    if (precomp) {
      member_ctx->precomp = *precomp;
    } else {
      sts = PrecomputeMemberPairing(member_ctx->epid2_params, pub_key,
                                    &priv_key->A, &member_ctx->precomp);
      BREAK_ON_EPID_ERROR(sts);
    }

    // complete initialization of TPM
    sts = TpmInit(member_ctx->tpm_ctx, &priv_key->A, &priv_key->x, &pub_key->h1,
                  &pub_key->h2, &pub_key->w, &member_ctx->precomp);
    BREAK_ON_EPID_ERROR(sts);

    *ctx = member_ctx;
    sts = kEpidNoErr;
  } while (0);

  if (kEpidNoErr != sts) {
    EpidMemberDelete(&member_ctx);
  }

  return (sts);
}

void EpidMemberDelete(MemberCtx** ctx) {
  if (ctx && *ctx) {
    TpmDelete(&(*ctx)->tpm_ctx);
    DeleteEpid2Params(&(*ctx)->epid2_params);
    DeleteBasenames(&(*ctx)->allowed_basenames);
    SAFE_FREE(*ctx);
  }
}

EpidStatus EpidMemberWritePrecomp(MemberCtx const* ctx,
                                  MemberPrecomp* precomp) {
  if (!ctx) {
    return kEpidBadArgErr;
  }
  if (!precomp) {
    return kEpidBadArgErr;
  }

  *precomp = ctx->precomp;
  return kEpidNoErr;
}

EpidStatus EpidMemberSetHashAlg(MemberCtx* ctx, HashAlg hash_alg) {
  if (!ctx) return kEpidBadArgErr;
  if (kSha256 != hash_alg && kSha384 != hash_alg && kSha512 != hash_alg &&
      kSha512_256 != hash_alg)
    return kEpidBadArgErr;
  ctx->hash_alg = hash_alg;
  return kEpidNoErr;
}

EpidStatus EpidMemberSetSigRl(MemberCtx* ctx, SigRl const* sig_rl,
                              size_t sig_rl_size) {
  if (!ctx || !sig_rl) {
    return kEpidBadArgErr;
  }
  if (!IsSigRlValid(&ctx->pub_key.gid, sig_rl, sig_rl_size)) {
    return kEpidBadArgErr;
  }
  // Do not set an older version of sig rl
  if (ctx->sig_rl) {
    unsigned int current_ver = 0;
    unsigned int incoming_ver = 0;
    current_ver = ntohl(ctx->sig_rl->version);
    incoming_ver = ntohl(sig_rl->version);
    if (current_ver >= incoming_ver) {
      return kEpidBadArgErr;
    }
  }
  ctx->sig_rl = sig_rl;

  return kEpidNoErr;
}

EpidStatus EpidRegisterBaseName(MemberCtx* ctx, void const* basename,
                                size_t basename_len) {
  EpidStatus sts = kEpidErr;
  if (basename_len == 0) {
    return kEpidBadArgErr;
  }
  if (!ctx || !basename) {
    return kEpidBadArgErr;
  }

  if (IsBasenameAllowed(ctx->allowed_basenames, basename, basename_len)) {
    return kEpidDuplicateErr;
  }

  sts = AllowBasename(ctx->allowed_basenames, basename, basename_len);

  return sts;
}

EpidStatus EpidAddPreSigs(MemberCtx* ctx, size_t number_presigs) {
  if (!ctx) {
    return kEpidBadArgErr;
  }

  return TpmAddPreSigs(ctx->tpm_ctx, number_presigs);
}

size_t EpidGetNumPreSigs(MemberCtx const* ctx) {
  if (!ctx) {
    return 0;
  }
  return TpmGetNumPreSigs(ctx->tpm_ctx);
}
