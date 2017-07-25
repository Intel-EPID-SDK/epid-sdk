/*############################################################################
  # Copyright 2017 Intel Corporation
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
 * \brief EpidDecompressPrivKey implementation.
 */

#include "epid/member/api.h"

#include "epid/member/tpm/context.h"
#include "epid/member/tpm/decompress.h"
#include "epid/common/src/epid2params.h"

#include "epid/member/tpm/src/types.h"
#include "epid/common/math/finitefield.h"

/// Handle Intel(R) EPID Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus EpidDecompressPrivKey(GroupPubKey const* pub_key,
                                 CompressedPrivKey const* compressed_privkey,
                                 PrivKey* priv_key) {
  EpidStatus sts = kEpidErr;

  Epid2Params_* params = NULL;
  TpmCtx* ctx = NULL;

  if (!pub_key || !compressed_privkey || !priv_key) {
    return kEpidBadArgErr;
  }

  do {
    PrivKey key = {0};
    sts = CreateEpid2Params(&params);
    BREAK_ON_EPID_ERROR(sts);

    sts = TpmCreate(NULL, NULL, params, &ctx);
    BREAK_ON_EPID_ERROR(sts);

    sts = TpmProvisionCompressed(ctx, &compressed_privkey->seed);
    BREAK_ON_EPID_ERROR(sts);

    sts = TpmDecompressKey(ctx, &pub_key->h1, &pub_key->w,
                           &compressed_privkey->ax, &key.A, &key.x);
    BREAK_ON_EPID_ERROR(sts);

    sts = WriteFfElement(params->Fp, ctx->secret.f, &key.f, sizeof(key.f));
    BREAK_ON_EPID_ERROR(sts);

    key.gid = pub_key->gid;
    *priv_key = key;

    sts = kEpidNoErr;
  } while (0);

  TpmDelete(&ctx);
  DeleteEpid2Params(&params);

  return sts;
}
