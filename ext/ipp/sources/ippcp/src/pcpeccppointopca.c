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
//     EC over Prime Finite Field (EC Point operations)
// 
//  Contents:
//     ippsECCPSetPoint()
//     ippsECCPSetPointAtInfinity()
//     ippsECCPGetPoint()
// 
//     ippsECCPCheckPoint()
//     ippsECCPComparePoint()
// 
//     ippsECCPNegativePoint()
//     ippsECCPAddPoint()
//     ippsECCPMulPointScalar()
// 
// 
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpeccp.h"


/*F*
//    Name: ippsECCPSetPoint
//
// Purpose: Converts regular affine coordinates EC point (pX,pY)
//          into internal presentation - montgomery projective.
//
// Returns:                Reason:
//    ippStsNullPtrErr        NULL == pECC
//                            NULL == pPoint
//                            NULL == pX
//                            NULL == pY
//
//    ippStsContextMatchErr   illegal pECC->idCtx
//                            illegal pX->idCtx
//                            illegal pY->idCtx
//                            illegal pPoint->idCtx
//
//    ippStsOutOfECErr        point out-of EC
//
//    ippStsNoErr             no errors
//
// Parameters:
//    pX          pointer to the regular affine coordinate X
//    pY          pointer to the regular affine coordinate Y
//    pPoint      pointer to the EC Point context
//    pECC        pointer to the ECCP context
//
// Note:
//    if B==0 and (x,y)=(0,y) then point at Infinity will be set up
//    if B!=0 and (x,y)=(0,0) then point at Infinity will be set up
//    else point with requested coordinates (x,y) wil be set up
//    There are no check validation inside!
//
*F*/
IPPFUN(IppStatus, ippsECCPSetPoint,(const IppsBigNumState* pX,
                                        const IppsBigNumState* pY,
                                        IppsECCPPointState* pPoint,
                                        IppsECCPState* pEC))
{
   /* test pEC */
   IPP_BAD_PTR1_RET(pEC);
   /* use aligned EC context */
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET(!ECP_TEST_ID(pEC), ippStsContextMatchErr);

   /* test pX and pY */
   IPP_BAD_PTR2_RET(pX,pY);
   pX = (IppsBigNumState*)( IPP_ALIGNED_PTR(pX, ALIGN_VAL) );
   pY = (IppsBigNumState*)( IPP_ALIGNED_PTR(pY, ALIGN_VAL) );
   IPP_BADARG_RET(!BN_VALID_ID(pX), ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pY), ippStsContextMatchErr);

   {
      IppStatus sts;

      IppsGFpState* pGF = ECP_GFP(pEC);
      gsModEngine* pGFE = GFP_PMA(pGF);
      int elemLen = GFP_FELEN(pGFE);
      IppsGFpElement elmX, elmY;

      cpGFpElementConstruct(&elmX, cpGFpGetPool(1, pGFE), elemLen);
      cpGFpElementConstruct(&elmY, cpGFpGetPool(1, pGFE), elemLen);
      do {
         BNU_CHUNK_T* pData = BN_NUMBER(pX);
         int ns = BN_SIZE(pX);
         sts = ippsGFpSetElement((Ipp32u*)pData, BITS2WORD32_SIZE(BITSIZE_BNU(pData, ns)), &elmX, pGF);
         if(ippStsNoErr!=sts) break;
         pData = BN_NUMBER(pY);
         ns = BN_SIZE(pY);
         sts = ippsGFpSetElement((Ipp32u*)pData, BITS2WORD32_SIZE(BITSIZE_BNU(pData, ns)), &elmY, pGF);
         if(ippStsNoErr!=sts) break;
         sts = ippsGFpECSetPoint(&elmX, &elmY, pPoint, pEC);
      } while(0);

      cpGFpReleasePool(2, pGFE);
      return sts;
   }
}


/*F*
//    Name: ippsECCPSetPointAtInfinity
//
// Purpose: Set point at Infinity
//
// Returns:                Reason:
//    ippStsNullPtrErr        NULL == pECC
//                            NULL == pPoint
//
//    ippStsContextMatchErr   illegal pECC->idCtx
//                            illegal pPoint->idCtx
//
//    ippStsNoErr             no errors
//
// Parameters:
//    pPoint      pointer to the EC Point context
//    pECC        pointer to the ECCP context
//
*F*/
IPPFUN(IppStatus, ippsECCPSetPointAtInfinity,(IppsECCPPointState* pPoint, IppsECCPState* pEC))
{
   return ippsGFpECSetPointAtInfinity(pPoint, pEC);
}


/*F*
//    Name: ippsECCPGetPoint
//
// Purpose: Converts  internal presentation EC point - montgomery projective
//          into regular affine coordinates EC point (pX,pY)
//
// Returns:                Reason:
//    ippStsNullPtrErr        NULL == pECC
//                            NULL == pPoint
//
//    ippStsContextMatchErr   illegal pECC->idCtx
//                            illegal pPoint->idCtx
//                            NULL != pX, illegal pX->idCtx
//                            NULL != pY, illegal pY->idCtx
//
//    ippStsNoErr             no errors
//
// Parameters:
//    pX          pointer to the regular affine coordinate X
//    pY          pointer to the regular affine coordinate Y
//    pLength     pointer to the length of coordinates
//    pPoint      pointer to the EC Point context
//    pECC        pointer to the ECCP context
//
*F*/
IPPFUN(IppStatus, ippsECCPGetPoint,(IppsBigNumState* pX, IppsBigNumState* pY,
                                  const IppsECCPPointState* pPoint,
                                  IppsECCPState* pEC))
{
   /* test pEC */
   IPP_BAD_PTR1_RET(pEC);
   /* use aligned EC context */
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET(!ECP_TEST_ID(pEC), ippStsContextMatchErr);

   /* test pX and pY */
   if(pX) {
      pX = (IppsBigNumState*)( IPP_ALIGNED_PTR(pX, ALIGN_VAL) );
      IPP_BADARG_RET(!BN_VALID_ID(pX), ippStsContextMatchErr);
   }
   if(pY) {
      pY = (IppsBigNumState*)( IPP_ALIGNED_PTR(pY, ALIGN_VAL) );
      IPP_BADARG_RET(!BN_VALID_ID(pY), ippStsContextMatchErr);
   }

   {
      IppStatus sts;

      IppsGFpState* pGF = ECP_GFP(pEC);
      gsModEngine* pGFE = GFP_PMA(pGF);
      int elemLen = GFP_FELEN(pGFE);

      mod_decode decode = GFP_METHOD(pGFE)->decode;  /* gf decode method  */

      IppsGFpElement elmX, elmY;

      cpGFpElementConstruct(&elmX, cpGFpGetPool(1, pGFE), elemLen);
      cpGFpElementConstruct(&elmY, cpGFpGetPool(1, pGFE), elemLen);
      do {
         sts = ippsGFpECGetPoint(pPoint, pX? &elmX:NULL, pY? &elmY:NULL, pEC);
         if(ippStsNoErr!=sts) break;

         if(pX) {
            decode(elmX.pData, elmX.pData, pGFE);
            sts = ippsSet_BN(ippBigNumPOS, GFP_FELEN32(pGFE), (Ipp32u*)elmX.pData, pX);
            if(ippStsNoErr!=sts) break;
         }
         if(pY) {
            decode(elmY.pData, elmY.pData, pGFE);
            sts = ippsSet_BN(ippBigNumPOS, GFP_FELEN32(pGFE), (Ipp32u*)elmY.pData, pY);
            if(ippStsNoErr!=sts) break;
         }
      } while(0);

      cpGFpReleasePool(2, pGFE);
      return sts;
   }
}


/*F*
//    Name: ippsECCPCheckPoint
//
// Purpose: Check EC point:
//             - is point lie on EC
//             - is point at infinity
//
// Returns:                Reason:
//    ippStsNullPtrErr        NULL == pECC
//                            NULL == pP
//                            NULL == pResult
//
//    ippStsContextMatchErr   illegal pECC->idCtx
//                            illegal pP->idCtx
//
//    ippStsNoErr             no errors
//
// Parameters:
//    pPoint      pointer to the EC Point context
//    pECC        pointer to the ECCP context
//    pResult     pointer to the result:
//                         ippECValid
//                         ippECPointIsNotValid
//                         ippECPointIsAtInfinite
//
*F*/
IPPFUN(IppStatus, ippsECCPCheckPoint,(const IppsECCPPointState* pP,
                                          IppECResult* pResult,
                                          IppsECCPState* pEC))
{
   return ippsGFpECTstPoint(pP, pResult, pEC);
}


/*F*
//    Name: ippsECCPComparePoint
//
// Purpose: Compare two EC points
//
// Returns:                Reason:
//    ippStsNullPtrErr        NULL == pECC
//                            NULL == pP
//                            NULL == pQ
//                            NULL == pResult
//
//    ippStsContextMatchErr   illegal pECC->idCtx
//                            illegal pP->idCtx
//                            illegal pQ->idCtx
//
//    ippStsNoErr             no errors
//
// Parameters:
//    pP          pointer to the EC Point context
//    pQ          pointer to the EC Point context
//    pECC        pointer to the ECCP context
//    pResult     pointer to the result:
//                         ippECPointIsEqual
//                         ippECPointIsNotEqual
//
*F*/
IPPFUN(IppStatus, ippsECCPComparePoint,(const IppsECCPPointState* pP,
                                            const IppsECCPPointState* pQ,
                                            IppECResult* pResult,
                                            IppsECCPState* pEC))
{
   return ippsGFpECCmpPoint(pP, pQ, pResult, pEC);
}


/*F*
//    Name: ippsECCPNegativePoint
//
// Purpose: Perforn EC point operation: R = -P
//
// Returns:                Reason:
//    ippStsNullPtrErr        NULL == pECC
//                            NULL == pP
//                            NULL == pR
//
//    ippStsContextMatchErr   illegal pECC->idCtx
//                            illegal pP->idCtx
//                            illegal pR->idCtx
//
//    ippStsNoErr             no errors
//
// Parameters:
//    pP          pointer to the source EC Point context
//    pR          pointer to the resultant EC Point context
//    pECC        pointer to the ECCP context
//
*F*/
IPPFUN(IppStatus, ippsECCPNegativePoint, (const IppsECCPPointState* pP,
                                              IppsECCPPointState* pR,
                                              IppsECCPState* pEC))
{
   return ippsGFpECNegPoint(pP, pR, pEC);
}


/*F*
//    Name: ippsECCPAddPoint
//
// Purpose: Perforn EC point operation: R = P+Q
//
// Returns:                Reason:
//    ippStsNullPtrErr        NULL == pECC
//                            NULL == pP
//                            NULL == pQ
//                            NULL == pR
//
//    ippStsContextMatchErr   illegal pECC->idCtx
//                            illegal pP->idCtx
//                            illegal pQ->idCtx
//                            illegal pR->idCtx
//
//    ippStsNoErr             no errors
//
// Parameters:
//    pP          pointer to the source EC Point context
//    pQ          pointer to the source EC Point context
//    pR          pointer to the resultant EC Point context
//    pECC        pointer to the ECCP context
//
*F*/
IPPFUN(IppStatus, ippsECCPAddPoint,(const IppsECCPPointState* pP,
                                        const IppsECCPPointState* pQ,
                                        IppsECCPPointState* pR,
                                        IppsECCPState* pEC))
{
   return ippsGFpECAddPoint(pP, pQ, pR, pEC);
}


/*F*
//    Name: ippsECCPMulPointScalar
//
// Purpose: Perforn EC point operation: R = k*P
//
// Returns:                Reason:
//    ippStsNullPtrErr        NULL == pECC
//                            NULL == pP
//                            NULL == pK
//                            NULL == pR
//
//    ippStsContextMatchErr   illegal pECC->idCtx
//                            illegal pP->idCtx
//                            illegal pK->idCtx
//                            illegal pR->idCtx
//
//    ippStsNoErr             no errors
//
// Parameters:
//    pP          pointer to the source EC Point context
//    pK          pointer to the source BigNum multiplier context
//    pR          pointer to the resultant EC Point context
//    pECC        pointer to the ECCP context
//
*F*/
IPPFUN(IppStatus, ippsECCPMulPointScalar,(const IppsECCPPointState* pP,
                                              const IppsBigNumState* pK,
                                              IppsECCPPointState* pR,
                                              IppsECCPState* pEC))
{
   /* use aligned EC context */
   IPP_BAD_PTR1_RET(pEC);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET(!ECP_TEST_ID(pEC), ippStsContextMatchErr);

   return ippsGFpECMulPoint(pP, pK, pR, pEC, (Ipp8u*)ECP_SBUFFER(pEC));
}
