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
//     EC over GF(p^m) Public Key Generation and Test KeyPair
// 
//  Contents:
//     ippsGFpECPrivateKey()
//     ippsGFpECPublicKey()
//     ippsGFpECTstKeyPair()
// 
// 
*/

#include "owndefs.h"
#include "owncp.h"

#include "pcpgfpecstuff.h"


/*F*
//    Name: ippsGFpECPrivateKey
//
// Purpose: Generate random private key
//
// Returns:                Reason:
//    ippStsNullPtrErr        NULL == pEC
//                            NULL == pPrivate
//
//    ippStsContextMatchErr   illegal pEC->idCtx
//                            illegal pPrivate->idCtx
//
//    ippStsNoErr             no errors
//
// Parameters:
//    pPrivate    pointer to the resultant private key
//    pEC         pointer to the EC context
//
*F*/
IPPFUN(IppStatus, ippsGFpECPrivateKey, (IppsBigNumState* pPrivate, IppsGFpECState* pEC,
                                        IppBitSupplier rndFunc, void* pRndParam))
{
   IPP_BAD_PTR2_RET(pEC, rndFunc);

   /* use aligned EC context */
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET(!ECP_TEST_ID(pEC), ippStsContextMatchErr);

   /* test private key */
   IPP_BAD_PTR1_RET(pPrivate);
   pPrivate = (IppsBigNumState*)( IPP_ALIGNED_PTR(pPrivate, ALIGN_VAL) );
   IPP_BADARG_RET(!BN_VALID_ID(pPrivate), ippStsContextMatchErr);
   IPP_BADARG_RET((BN_ROOM(pPrivate)*BITSIZE(BNU_CHUNK_T)<ECP_ORDBITSIZE(pEC)), ippStsSizeErr);

   {
      /* generate random private key X:  0 < X < R */
      BNU_CHUNK_T* pOrder = MOD_MODULUS(ECP_MONT_R(pEC));
      int orderBitLen = ECP_ORDBITSIZE(pEC);
      int orderLen = BITS_BNU_CHUNK(orderBitLen);

      BNU_CHUNK_T* pX = BN_NUMBER(pPrivate);
      int nsX = BITS_BNU_CHUNK(orderBitLen);
      BNU_CHUNK_T xMask = MASK_BNU_CHUNK(orderBitLen);

      IppStatus sts;
      do {
         sts = rndFunc((Ipp32u*)pX, orderBitLen, pRndParam);
         if(ippStsNoErr!=sts)
            break;
         pX[nsX-1] &= xMask;
      } while( (1 == cpEqu_BNU_CHUNK(pX, nsX, 0)) ||
               (0 <= cpCmp_BNU(pX, nsX, pOrder, orderLen)) );

      /* set up private */
      if(ippStsNoErr==sts) {
         BN_SIGN(pPrivate) = ippBigNumPOS;
         FIX_BNU(pX, nsX);
         BN_SIZE(pPrivate) = nsX;
      }

      return sts;
   }
}


/*F*
//    Name: ippsGFpECPublicKey
//
// Purpose: Compute Public Key
//
// Returns:                Reason:
//    ippStsNullPtrErr        NULL == pEC
//                            NULL == pPrivate
//                            NULL == pPublic
//                            NULL == pScratchBuffer
//
//    ippStsContextMatchErr   illegal pEC->idCtx
//                            illegal pPrivate->idCtx
//                            illegal pPublic->idCtx
//
//    ippStsIvalidPrivateKey  !(0 < pPrivate < order)
//
//    ippStsNoErr             no errors
//
// Parameters:
//    pPrivate       pointer to the private key
//    pPublic        pointer to the resultant public key
//    pEC            pointer to the EC context
//    pScratchBuffer pointer to buffer (1 mul_point operation)
//
*F*/
IPPFUN(IppStatus, ippsGFpECPublicKey, (const IppsBigNumState* pPrivate, IppsGFpECPoint* pPublic,
                                      IppsGFpECState* pEC, Ipp8u* pScratchBuffer))
{
   /* EC context and buffer */
   IPP_BAD_PTR2_RET(pEC, pScratchBuffer);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET(!ECP_TEST_ID(pEC), ippStsContextMatchErr);

   /* test private keys */
   IPP_BAD_PTR1_RET(pPrivate);
   pPrivate = (IppsBigNumState*)( IPP_ALIGNED_PTR(pPrivate, ALIGN_VAL) );
   IPP_BADARG_RET(!BN_VALID_ID(pPrivate), ippStsContextMatchErr);

   /* test public key */
   IPP_BAD_PTR1_RET(pPublic);
   IPP_BADARG_RET(!ECP_POINT_TEST_ID(pPublic), ippStsContextMatchErr);
   IPP_BADARG_RET(ECP_POINT_FELEN(pPublic)<GFP_FELEN(GFP_PMA(ECP_GFP(pEC))), ippStsRangeErr);

   {
      BNU_CHUNK_T* pS= BN_NUMBER(pPrivate);
      int nsS= BN_SIZE(pPrivate);

      BNU_CHUNK_T* pOrder = MOD_MODULUS(ECP_MONT_R(pEC));
      int orderLen = BITS_BNU_CHUNK(ECP_ORDBITSIZE(pEC));

      IPP_BADARG_RET(cpEqu_BNU_CHUNK(pS, nsS, 0)
               || 0<=cpCmp_BNU(pS, nsS, pOrder, orderLen), ippStsIvalidPrivateKey);

      /* calculates public key */
      gfec_MulBasePoint(pPublic, pS, nsS, pEC, pScratchBuffer);

      return ippStsNoErr;
   }
}


/*F*
//    Name: ippsGFpECTstKeyPair
//
// Purpose: Test Key Pair
//
// Returns:                Reason:
//    ippStsNullPtrErr        NULL == pEC
//                            NULL == pPrivate
//                            NULL == pPublic
//                            NULL == pResult
//                            NULL == pScratchBuffer
//
//    ippStsContextMatchErr   illegal pEC->idCtx
//                            illegal pPrivate->idCtx
//                            illegal pPublic->idCtx
//
//    ippStsNoErr             no errors
//
// Parameters:
//    pPrivate       pointer to the private key
//    pPublic        pointer to the public  key
//    pResult        pointer to the result:
//                   ippECValid/ippECInvalidPrivateKey/ippECPointIsAtInfinite/ippECInvalidPublicKey
//    pEC            pointer to the EC context
//    pScratchBuffer pointer to buffer (1 mul_point operation)
//
*F*/
IPPFUN(IppStatus, ippsGFpECTstKeyPair, (const IppsBigNumState* pPrivate, const IppsGFpECPoint* pPublic, IppECResult* pResult,
                                        IppsGFpECState* pEC, Ipp8u* pScratchBuffer))
{
   /* EC context and buffer */
   IPP_BAD_PTR2_RET(pEC, pScratchBuffer);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET(!ECP_TEST_ID(pEC), ippStsContextMatchErr);

   /* test result */
   IPP_BAD_PTR1_RET(pResult);
   *pResult = ippECValid;

   /* private key validation request */
   if( pPrivate ) {
      pPrivate = (IppsBigNumState*)( IPP_ALIGNED_PTR(pPrivate, ALIGN_VAL) );
      IPP_BADARG_RET(!BN_VALID_ID(pPrivate), ippStsContextMatchErr);

      {
         BNU_CHUNK_T* pS = BN_NUMBER(pPrivate);
         int nsS = BN_SIZE(pPrivate);

         BNU_CHUNK_T* pOrder = MOD_MODULUS(ECP_MONT_R(pEC));
         int orderLen = BITS_BNU_CHUNK(ECP_ORDBITSIZE(pEC));

         /* check private key */
         if(cpEqu_BNU_CHUNK(pS, nsS, 0) || 0<=cpCmp_BNU(pS, nsS, pOrder, orderLen)) {
            *pResult = ippECInvalidPrivateKey;
            return ippStsNoErr;
         }
      }
   }

   /* public key validation request */
   if( pPublic ) {
      IPP_BADARG_RET( !ECP_POINT_TEST_ID(pPublic), ippStsContextMatchErr );
      IPP_BADARG_RET(ECP_POINT_FELEN(pPublic)<GFP_FELEN(GFP_PMA(ECP_GFP(pEC))), ippStsRangeErr);

      {
         IppsGFpECPoint T;
         cpEcGFpInitPoint(&T, cpEcGFpGetPool(1, pEC),0, pEC);

         do {
            /* public != point_at_Infinity */
            if( gfec_IsPointAtInfinity(pPublic) ) {
               *pResult = ippECPointIsAtInfinite;
               break;
            }
            /* order*public == point_at_Infinity */
            gfec_MulPoint(&T, pPublic, MOD_MODULUS(ECP_MONT_R(pEC)), BITS_BNU_CHUNK(ECP_ORDBITSIZE(pEC)), pEC, pScratchBuffer);
            if( !gfec_IsPointAtInfinity(&T) ) {
               *pResult = ippECInvalidPublicKey;
               break;
            }
            /* addition test: private*BasePoint == public */
            if(pPrivate) {
               gfec_MulBasePoint(&T, BN_NUMBER(pPrivate), BN_SIZE(pPrivate), pEC, pScratchBuffer);
               if(!gfec_ComparePoint(&T, pPublic, pEC))
                  *pResult = ippECInvalidKeyPair;
            }
         } while(0);

         cpEcGFpReleasePool(1, pEC);
      }
   }

   return ippStsNoErr;
}
