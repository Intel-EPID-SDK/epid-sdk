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
/// TPM2_FlushContext command implementation.
/*! \file */

#include "epid/member/split/tpm2/flushcontext.h"

#include "epid/common/src/memory.h"
#include "epid/common/types.h"
#include "epid/member/split/tpm2/ibm_tss/printtss.h"
#include "epid/member/split/tpm2/ibm_tss/state.h"
#include "tss2/TPM_Types.h"
#include "tss2/tss.h"

EpidStatus Tpm2FlushContext(Tpm2Ctx* ctx, Tpm2Key** key) {
  TPM_RC rc = TPM_RC_SUCCESS;
  size_t i = 0;
  EpidStatus sts = kEpidNoErr;

  if (!ctx || !key || !(*key)) {
    return kEpidBadArgErr;
  }

  for (i = 0; i < ctx->max_keys; i++) {
    if (*key == ctx->keys[i]) {
      if ((*key)->handle) {
        FlushContext_In in_fc;
        in_fc.flushHandle = (*key)->handle;
        TSS_Execute(ctx->tss, NULL, (COMMAND_PARAMETERS*)&in_fc, NULL,
                    TPM_CC_FlushContext, TPM_RH_NULL, NULL, 0);
        if (rc != TPM_RC_SUCCESS) {
          print_tpm2_response_code("TPM2_FlushContext", rc);
          sts = kEpidErr;
        }
        (*key)->handle = 0;
      }
      SAFE_FREE(*key);
      ctx->keys[i] = NULL;
      break;
    }
  }
  if (i == ctx->max_keys) {
    return kEpidBadArgErr;
  }

  return sts;
}
