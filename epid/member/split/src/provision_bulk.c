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
/// EpidProvisionKey implementation.
/*! \file */
#define EXPORT_EPID_APIS
#include <epid/member/api.h>

#include <string.h>
#include "common/gid_parser.h"
#include "common/validate_privkey.h"
#include "epid/member/split/context.h"
#include "epid/member/split/storage.h"
#include "epid/member/split/tpm2/context.h"
#include "epid/member/split/tpm2/flushcontext.h"
#include "epid/member/split/tpm2/load_external.h"
#include "epid/stdtypes.h"
#include "epid/types.h"
#include "ippmath/memory.h"

/// Handle SDK Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus EPID_MEMBER_API EpidProvisionKey(MemberCtx* ctx,
                                            GroupPubKey const* pub_key,
                                            PrivKey const* priv_key,
                                            MemberPrecomp const* precomp_str) {
  EpidStatus sts = kEpidErr;

  Tpm2Key* new_f_handle = NULL;

  if (!pub_key || !priv_key || !ctx) {
    return kEpidBadArgErr;
  }

  // The member verifies that gid in public key and in private key
  // match. If mismatch, abort and return operation failed.
  if (memcmp(&pub_key->gid, &priv_key->gid, sizeof(GroupId))) {
    return kEpidKeyNotInGroupErr;
  }

  do {
    MembershipCredential credential = {0};
    HashAlg hash_alg = kInvalidHashAlg;
    // set the default hash algorithm
    sts = EpidParseHashAlg(&pub_key->gid, &hash_alg);
    BREAK_ON_EPID_ERROR(sts);

    if (kSha256 != hash_alg && kSha384 != hash_alg && kSha512 != hash_alg &&
        kSha512_256 != hash_alg) {
      sts = kEpidHashAlgorithmNotSupported;
      BREAK_ON_EPID_ERROR(sts);
    }

    credential.A = priv_key->A;
    credential.x = priv_key->x;
    credential.gid = priv_key->gid;

    sts =
        Tpm2LoadExternal(ctx->tpm2_ctx, hash_alg, &priv_key->f, &new_f_handle);
    BREAK_ON_EPID_ERROR(sts);

    /////// validate
    sts = EpidValidateSplitPrivateKey(priv_key, pub_key);
    BREAK_ON_EPID_ERROR(sts);
    ///////

    sts = EpidNvWriteMembershipCredential(ctx->tpm2_ctx, pub_key, &credential);
    BREAK_ON_EPID_ERROR(sts);

    if (ctx->f_handle) {
      Tpm2FlushContext(ctx->tpm2_ctx, &ctx->f_handle);
    }
    ctx->f_handle = new_f_handle;

    if (precomp_str) {
      ctx->precomp = *precomp_str;
      ctx->precomp_ready = true;
    } else {
      EpidZeroMemory(&ctx->precomp, sizeof(ctx->precomp));
      ctx->precomp_ready = false;
    }

    ctx->pub_key = *pub_key;
    ctx->is_provisioned = true;

    ctx->credential.A = credential.A;
    ctx->credential.x = credential.x;
    ctx->credential.gid = credential.gid;
  } while (0);

  if (kEpidNoErr != sts) {
    Tpm2FlushContext(ctx->tpm2_ctx, &new_f_handle);
  }

  return sts;
}
