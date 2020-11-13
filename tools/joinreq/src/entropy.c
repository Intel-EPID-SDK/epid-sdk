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
/// Random data supplier implementation.
/*! \file */
#include "entropy.h"

#include <errno.h>
#include <limits.h>  // for CHAR_BIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif  // defined(_WIN32)

#include "prng.h"
#include "util/envutil.h"

typedef struct BitSupplierCtx {
  FILE* randfile;
  void* prng;

  // SupplyBits error flag
  int not_enough_entropy_bytes;
} BitSupplierCtx;

void* NewBitSupplier(char const* filename) {
  BitSupplierCtx* ctx = NULL;
  EpidStatus sts = kEpidNoErr;
  errno = 0;
  do {
    ctx = (BitSupplierCtx*)malloc(sizeof(BitSupplierCtx));
    if (!ctx) break;

    if (filename) {
      ctx->prng = NULL;
      if ('-' == filename[0] && 0 == filename[1]) {
// use entropy from stdin
#if defined(_WIN32)
        _setmode(_fileno(stdin), _O_BINARY);
#endif  // defined(_WIN32)
        ctx->randfile = stdin;
      } else {
        // use entropy from file
        ctx->randfile = fopen(filename, "rb");
        if (!ctx->randfile) {
          log_error("%s: cannot open %s", filename, strerror(errno));
          // log_error("%s: %s", filename, strerror(errno));
          sts = kEpidErr;
          break;
        }
      }
    } else {
      // use PRNG
      ctx->randfile = NULL;
      sts = PrngCreate(&ctx->prng);
    }
    ctx->not_enough_entropy_bytes = 0;
  } while (0);

  if (kEpidNoErr != sts) {
    DeleteBitSupplier((void**)&ctx);
  }

  return ctx;
}

void DeleteBitSupplier(void** bs_ctx) {
  BitSupplierCtx* ctx = (BitSupplierCtx*)*bs_ctx;
  if (ctx) {
    if (ctx->randfile) {
      fclose(ctx->randfile);
    }
    if (ctx->prng) {
      PrngDelete(&ctx->prng);
    }
    ctx->not_enough_entropy_bytes = 0;
    free(*bs_ctx);
    *bs_ctx = NULL;
  }
}

int __STDCALL SupplyBits(unsigned int* rand_data, int num_bits,
                         void* user_data) {
  BitSupplierCtx* ctx = (BitSupplierCtx*)user_data;
  if (ctx && ctx->randfile) {
    size_t bytes_read = 0;
    unsigned int num_bytes = (num_bits + CHAR_BIT - 1) / CHAR_BIT;
    bytes_read = fread(rand_data, 1, num_bytes, ctx->randfile);
    if (bytes_read == num_bytes) {
      return 0;
    } else {
      ctx->not_enough_entropy_bytes = 1;
      return -1;
    }
  } else if (ctx && ctx->prng) {
    return PrngGen(rand_data, num_bits, ctx->prng);
  }
  return -1;
}

int NotEnoughBytesOfEntropyProvided(void* bs_ctx) {
  BitSupplierCtx* ctx = (BitSupplierCtx*)bs_ctx;
  if (ctx->not_enough_entropy_bytes) {
    return 1;
  }
  return 0;
}
