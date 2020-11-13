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
/// Tiny stack container interface.
/*! \file */

#ifndef EPID_MEMBER_TINY_SRC_STACK_H_
#define EPID_MEMBER_TINY_SRC_STACK_H_

#include <stddef.h>
#include "epid/member/tiny/presig_compute.h"
#include "epid/stdtypes.h"

/// Internal representation of a Stack
typedef struct Stack {
  PreComputedSignatureData* buf;  ///< pointer to pre-computed signature
  size_t max_size;  ///< Numbers of presigs buffer was allocated to
  size_t top;       ///< Stack top, the number of elements in the stack
} Stack;

/// Initialize precomputed signatures container
/*!
\param[in,out] presig_container
Stack context
\param[in] num_presigs
Number of elements intended to save in the pool
\param[in] heap
Buffer to point as a pool
*/
void InitPreSigStack(Stack* presig_container, size_t num_presigs, void* heap);

/// Get number of elements in the stack
/*!
\param[in] stack
Stack context

\returns Number of elements in the stack or 0 if stack is NULL

*/
size_t StackGetSize(Stack const* stack);
/// Push multiple elements to the stack
/*!
  \param[in,out] stack
  Stack context
  \param[in] n
  Number of elements to push to the stack
  \param[in] elements
  Array of elements to push to the stack. Can be NULL

  \returns A pointer to an array of new elements in the stack or NULL if
    stack is empty or push operation failed.

*/
PreComputedSignatureData* StackPushN(Stack* stack, size_t n,
                                     PreComputedSignatureData* elements);

/// Return a pointer to the top element in the stack
/*!
  \warning
  You must call StackPopN() immediately after using the pre-
  computed signature provided by this function or you risk exposing
  the member private key.

  \param[in] stack
  Stack context

  \returns A pointer to the top element in the stack or NULL if
    stack is empty or top operation failed.

  \see StackPopN
*/
PreComputedSignatureData* StackTop(Stack* stack);

/// Pop multiple elements from the stack
/*!
\param[in,out] stack
Stack context
\param[in] n
Number of elements to pop from the stack

\returns true if operation succeed, false otherwise

*/
bool StackPopN(Stack* stack, size_t n);

#endif  // EPID_MEMBER_TINY_SRC_STACK_H_
