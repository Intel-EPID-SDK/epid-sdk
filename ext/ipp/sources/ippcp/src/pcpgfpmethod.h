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

/* 
//  Purpose:
//     Intel(R) Integrated Performance Primitives
//     Cryptographic Primitives
//     Internal GF(p) basic Definitions & Function Prototypes
//
*/
#if !defined(_CP_GFP_METHOD_H)
#define _CP_GFP_METHOD_H

#include "owndefs.h"
#include "owncp.h"

#include "pcpbnuimpl.h"

/* GF methods */
typedef BNU_CHUNK_T* (*gfadd) (BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGF);
typedef BNU_CHUNK_T* (*gfsub) (BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGF);
typedef BNU_CHUNK_T* (*gfneg) (BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF);
typedef BNU_CHUNK_T* (*gfdiv2)(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF);
typedef BNU_CHUNK_T* (*gfmul2)(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF);
typedef BNU_CHUNK_T* (*gfmul3)(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF);
typedef BNU_CHUNK_T* (*gfmul) (BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGF);
typedef BNU_CHUNK_T* (*gfsqr) (BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF);
typedef BNU_CHUNK_T* (*gfencode)(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF);
typedef BNU_CHUNK_T* (*gfdecode)(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF);

typedef struct _cpGFpMethod {
   gfadd    add;
   gfsub    sub;
   gfneg    neg;
   gfdiv2   div2;
   gfmul2   mul2;
   gfmul3   mul3;
   gfmul    mul;
   gfsqr    sqr;
   gfencode encode;
   gfdecode decode;
} cpGFpMethod;

#endif /* _CP_GFP_METHOD_H */
