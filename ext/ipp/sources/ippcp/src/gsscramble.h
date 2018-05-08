/*############################################################################
  # Copyright 2013-2018 Intel Corporation
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

/* 
// 
//  Purpose:
//     Cryptography Primitive.
//     Fixed window exponentiation scramble/unscramble
// 
//  Contents:
//    gsGetScrambleBufferSize()
//    gsScramblePut()
//    gsScrambleGet()
//    gsScrambleGet_sscm()
// 
// 
*/

#if !defined(_GS_SCRAMBLE_H)
#define _GS_SCRAMBLE_H

#include "pcpbnuimpl.h"

#define MAX_W  (6)

__INLINE unsigned int ct_msb(unsigned int a)
{
   return 0 - (a >> (sizeof(a) * 8 - 1));
}

__INLINE unsigned int ct_is_zero(unsigned int a)
{
   return ct_msb(~a & (a - 1));
}

__INLINE unsigned int ct_eq(unsigned int a, unsigned int b)
{
   return ct_is_zero(a ^ b);
}

__INLINE unsigned int ct_eq_int(int a, int b)
{
   return ct_eq((unsigned)(a), (unsigned)(b));
}

#define gsGetScrambleBufferSize OWNAPI(gsGetScrambleBufferSize)
int     gsGetScrambleBufferSize(int modulusLen, int w);

#define gsScramblePut OWNAPI(gsScramblePut)
void gsScramblePut(BNU_CHUNK_T* tbl, int idx, const BNU_CHUNK_T* val, int vLen, int w);

#define gsScrambleGet OWNAPI(gsScrambleGet)
void gsScrambleGet(BNU_CHUNK_T* val, int vLen, const BNU_CHUNK_T* tbl, int idx, int w);

#define gsScrambleGet_sscm OWNAPI(gsScrambleGet_sscm)
void gsScrambleGet_sscm(BNU_CHUNK_T* val, int vLen, const BNU_CHUNK_T* tbl, int idx, int w);

#endif /* _GS_SCRAMBLE_H */
