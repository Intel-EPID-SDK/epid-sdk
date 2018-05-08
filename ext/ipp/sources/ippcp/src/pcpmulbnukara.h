/*############################################################################
  # Copyright 1999-2018 Intel Corporation
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
//     BN Multiplication (Karatsuba method) Definitions & Function Prototypes
// 
//  Contents:
//     cpKaratsubaBufferSize()
//     cpMul_BNU_karatuba()
//     cpSqr_BNU_karatuba()
//     cpKAdd_BNU()
//     cpKSub_BNU()
// 
// 
*/

#if !defined(_KARATSUBA_MUL_)
#define _KARATSUBA_MUL_

#if defined(_USE_KARATSUBA_)

#if((_IPP==_IPP_W7) || \
    (_IPP==_IPP_T7))
   #define CP_KARATSUBA_MUL_THRESHOLD 16
   #define CP_KARATSUBA_SQR_THRESHOLD 32
#elif ((_IPP==_IPP_V8) || \
       (_IPP==_IPP_P8) || \
       (_IPP==_IPP_G9) || \
       (_IPP==_IPP_S8))
   #define CP_KARATSUBA_MUL_THRESHOLD 32
   #define CP_KARATSUBA_SQR_THRESHOLD 32
#elif ((_IPP>=_IPP_H9))
   #define CP_KARATSUBA_MUL_THRESHOLD 32
   #define CP_KARATSUBA_SQR_THRESHOLD 32

#elif ((_IPP32E==_IPP32E_M7) || \
       (_IPP32E==_IPP32E_U8) || \
       (_IPP32E==_IPP32E_Y8) || \
       (_IPP32E==_IPP32E_E9) || \
       (_IPP32E==_IPP32E_N8))
   #define CP_KARATSUBA_MUL_THRESHOLD 16
   #define CP_KARATSUBA_SQR_THRESHOLD 40
#elif ((_IPP32E>=_IPP32E_L9))
   #define CP_KARATSUBA_MUL_THRESHOLD 20
   #define CP_KARATSUBA_SQR_THRESHOLD 48

#else
   #define CP_KARATSUBA_MUL_THRESHOLD 12
   #define CP_KARATSUBA_SQR_THRESHOLD 16
#endif


#define cpKaratsubaBufferSize OWNAPI(cpKaratsubaBufferSize)
cpSize cpKaratsubaBufferSize(cpSize len);

#define cpMul_BNU_karatsuba OWNAPI(cpMul_BNU_karatsuba)
BNU_CHUNK_T cpMul_BNU_karatsuba(BNU_CHUNK_T* pR,
                          const BNU_CHUNK_T* pX, const BNU_CHUNK_T* pY, cpSize ns,
                                BNU_CHUNK_T* pBuffer);
#define cpSqr_BNU_karatsuba OWNAPI(cpSqr_BNU_karatsuba)
BNU_CHUNK_T cpSqr_BNU_karatsuba(BNU_CHUNK_T* pR,
                          const BNU_CHUNK_T* pX, cpSize ns,
                                BNU_CHUNK_T* pBuffer);


#else
   #define CP_KARATSUBA_MUL_THRESHOLD 0
   #define CP_KARATSUBA_SQR_THRESHOLD 0
#endif /* _USE_KARATSUBA_ */

#endif /* _KARATSUBA_MUL_ */
