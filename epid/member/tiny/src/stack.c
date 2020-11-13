/*############################################################################
# Copyright 2018-2020 Intel Corporation
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
/// Tiny stack container implementation.
/*! \file */

#include "epid/member/tiny/stack.h"
#include "epid/member/tiny/presig_compute.h"
#include "tinystdlib/tiny_stdlib.h"

void InitPreSigStack(Stack* presig_container, size_t num_presigs, void* heap) {
  presig_container->max_size = num_presigs;
  presig_container->buf = heap;
  memset(presig_container->buf, 0,
         sizeof(PreComputedSignatureData) * num_presigs);
}

PreComputedSignatureData* StackPushN(Stack* stack, size_t n,
                                     PreComputedSignatureData* elements) {
  size_t i = 0;
  if (!stack || !stack->buf) return 0;
  if (stack->top + n > stack->max_size) {
    return NULL;
  }
  if (elements) {
    for (i = 0; i < n; i++) {
      stack->buf[stack->top + i] = elements[i];
    }
  }
  stack->top += n;
  return &stack->buf[stack->top - n];
}
PreComputedSignatureData* StackTop(Stack* stack) {
  if (!stack || !stack->buf) return NULL;
  if (!stack->top) return NULL;
  return &stack->buf[stack->top - 1];
}
bool StackPopN(Stack* stack, size_t n) {
  if (!stack || !stack->buf) return false;
  if (n > stack->top) return false;
  stack->top -= n;
  return true;
}
size_t StackGetSize(Stack const* stack) {
  return (stack && stack->buf) ? stack->top : (size_t)0;
}
