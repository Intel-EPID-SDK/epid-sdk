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
/// EpidProvisionCredential implementation.
/*! \file */

#define EXPORT_EPID_APIS
#include <epid/member/api.h>

#include <string.h>
#include "epid/member/split/context.h"
#include "epid/member/split/storage.h"
#include "epid/member/split/validatekey.h"
#include "epid/member/split/tpm2/context.h"
#include "epid/member/split/tpm2/createprimary.h"
#include "epid/member/split/tpm2/flushcontext.h"
#include "epid/member/split/tpm2/load_external.h"
#include "epid/types.h"
#include "ippmath/memory.h"

#include "common/gid_parser.h"

/// Handle SDK Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus EPID_MEMBER_API EpidProvisionCredential(
    MemberCtx* ctx, GroupPubKey const* pub_key,
    MembershipCredential const* credential, MemberPrecomp const* precomp_str) {
  EpidStatus sts = kEpidErr;
  Tpm2Key* f_handle = NULL;

  if (!pub_key || !credential || !ctx) {
    return kEpidBadArgErr;
  }

  if (memcmp(&pub_key->gid, &credential->gid, sizeof(GroupId))) {
    return kEpidKeyNotInGroupErr;
  }

  do {
    HashAlg hash_alg = kInvalidHashAlg;
    // set the default hash algorithm
    sts = EpidParseHashAlg(&pub_key->gid, &hash_alg);
    BREAK_ON_EPID_ERROR(sts);

    sts = CreatePrivateF(ctx, hash_alg, &f_handle);
    BREAK_ON_EPID_ERROR(sts);

    if (!EpidMemberIsKeyValid(ctx, &credential->A, &credential->x, f_handle,
                              &pub_key->h1, &pub_key->w)) {
      sts = kEpidKeyNotInGroupErr;
      break;
    }

    sts = EpidNvWriteMembershipCredential(ctx->tpm2_ctx, pub_key, credential);
    BREAK_ON_EPID_ERROR(sts);

    if (ctx->f_handle) {
      Tpm2FlushContext(ctx->tpm2_ctx, &ctx->f_handle);
    }
    ctx->f_handle = f_handle;

    if (precomp_str) {
      ctx->precomp = *precomp_str;
      ctx->precomp_ready = true;
    } else {
      EpidZeroMemory(&ctx->precomp, sizeof(ctx->precomp));
      ctx->precomp_ready = false;
    }

    ctx->credential.A = credential->A;
    ctx->credential.x = credential->x;
    ctx->credential.gid = credential->gid;
    ctx->pub_key = *pub_key;
    ctx->is_provisioned = true;
  } while (0);

  if (kEpidNoErr != sts) {
    Tpm2FlushContext(ctx->tpm2_ctx, &f_handle);
  }

  return sts;
}
