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
//     SM2 signature generation and verification
// 
//  Contents:
//     ippsGFpECSignSM2()
//     ippsGFpECVerifySM2()
// 
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpeccp.h"


/*F*
//    Name: ippsGFpECSignSM2
//
// Purpose: SM2 Signature Generation.
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == pEC
//                               NULL == pMsg
//                               NULL == pRegPrivate
//                               NULL == pEphPrivate
//                               NULL == pSignR
//                               NULL == pSignS
//                               NULL == pScratchBuffer
//
//    ippStsContextMatchErr      illegal pEC->idCtx
//                               illegal pMsg->idCtx
//                               illegal pRegPrivate->idCtx
//                               illegal pEphPrivate->idCtx
//                               illegal pSignR->idCtx
//                               illegal pSignS->idCtx
//
//    ippStsMessageErr           Msg < 0
//
//    ippStsRangeErr             not enough room for:
//                               signR
//                               signS
//
//    ippECInvalidSignature      (0==signR)
//                               (0==signS)
//                               (signR + ephPrivate) == order
//                               (1 + regPrivate) == order
//
//    ippStsNoErr                no errors
//
// Parameters:
//    pMsg           pointer to the message representative to be signed
//    pRegPrivate    pointer to the regular private key
//    pEphPrivate    pointer to the ephemeral private key
//    pSignR,pSignS  pointer to the signature
//    pEC            pointer to the EC context
//    pScratchBuffer pointer to buffer (1 mul_point operation)
//
*F*/
IPPFUN(IppStatus, ippsGFpECSignSM2,(const IppsBigNumState* pMsg,
                                    const IppsBigNumState* pRegPrivate,
                                    const IppsBigNumState* pEphPrivate,
                                    IppsBigNumState* pSignR, IppsBigNumState* pSignS,
                                    IppsGFpECState* pEC,
                                    Ipp8u* pScratchBuffer))
{
   IppsGFpState*  pGF;
   gsModEngine* pGFE;

   /* EC context and buffer */
   IPP_BAD_PTR2_RET(pEC, pScratchBuffer);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET(!ECP_TEST_ID(pEC), ippStsContextMatchErr);

   pGF = ECP_GFP(pEC);
   pGFE = GFP_PMA(pGF);
   IPP_BADARG_RET(1<GFP_EXTDEGREE(pGFE), ippStsNotSupportedModeErr);

   /* test message representative */
   IPP_BAD_PTR1_RET(pMsg);
   pMsg = (IppsBigNumState*)( IPP_ALIGNED_PTR(pMsg, ALIGN_VAL) );
   IPP_BADARG_RET(!BN_VALID_ID(pMsg), ippStsContextMatchErr);
   IPP_BADARG_RET(BN_NEGATIVE(pMsg), ippStsMessageErr);

   /* test signature */
   IPP_BAD_PTR2_RET(pSignS, pSignR);
   pSignR = (IppsBigNumState*)( IPP_ALIGNED_PTR(pSignR, ALIGN_VAL) );
   pSignS = (IppsBigNumState*)( IPP_ALIGNED_PTR(pSignS, ALIGN_VAL) );
   IPP_BADARG_RET(!BN_VALID_ID(pSignR), ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pSignS), ippStsContextMatchErr);
   IPP_BADARG_RET((BN_ROOM(pSignR)*BITSIZE(BNU_CHUNK_T)<ECP_ORDBITSIZE(pEC)), ippStsRangeErr);
   IPP_BADARG_RET((BN_ROOM(pSignS)*BITSIZE(BNU_CHUNK_T)<ECP_ORDBITSIZE(pEC)), ippStsRangeErr);

   /* test private keys */
   IPP_BAD_PTR2_RET(pRegPrivate, pEphPrivate);
   pRegPrivate = (IppsBigNumState*)( IPP_ALIGNED_PTR(pRegPrivate, ALIGN_VAL) );
   IPP_BADARG_RET(!BN_VALID_ID(pRegPrivate), ippStsContextMatchErr);
   pEphPrivate = (IppsBigNumState*)( IPP_ALIGNED_PTR(pEphPrivate, ALIGN_VAL) );
   IPP_BADARG_RET(!BN_VALID_ID(pEphPrivate), ippStsContextMatchErr);

   {
      gsModEngine* pMontR = ECP_MONT_R(pEC);
      BNU_CHUNK_T* pOrder = MOD_MODULUS(pMontR);
      int orderLen = MOD_LEN(pMontR);

      BNU_CHUNK_T* dataR = BN_NUMBER(pSignR);
      BNU_CHUNK_T* dataS = BN_NUMBER(pSignS);
      BNU_CHUNK_T* buffR = BN_BUFFER(pSignR);
      BNU_CHUNK_T* buffS = BN_BUFFER(pSignS);
      BNU_CHUNK_T* buffMsg = BN_BUFFER(pMsg);

      /* test value of private keys: regPrivate<order, ephPrivate<order */
      IPP_BADARG_RET(BN_NEGATIVE(pRegPrivate) ||
                     (0<=cpCmp_BNU(BN_NUMBER(pRegPrivate), BN_SIZE(pRegPrivate), pOrder, orderLen)), ippStsIvalidPrivateKey);
      IPP_BADARG_RET(BN_NEGATIVE(pEphPrivate) ||
                     (0<=cpCmp_BNU(BN_NUMBER(pEphPrivate), BN_SIZE(pEphPrivate), pOrder, orderLen)), ippStsIvalidPrivateKey);

      /* test value of private key: (regPrivate+1) != order */
      ZEXPAND_COPY_BNU(dataS,orderLen, BN_NUMBER(pRegPrivate),BN_SIZE(pRegPrivate));
      cpInc_BNU(dataS, dataS, orderLen, 1);
      IPP_BADARG_RET(0==cpCmp_BNU(dataS, orderLen, pOrder, orderLen), ippStsIvalidPrivateKey);

      {
         int elmLen = GFP_FELEN(pGFE);
         int ns;

         /* compute ephemeral public key */
         IppsGFpECPoint ephPublic;
         cpEcGFpInitPoint(&ephPublic, cpEcGFpGetPool(1, pEC), 0, pEC);
         gfec_MulBasePoint(&ephPublic,
                           BN_NUMBER(pEphPrivate), BN_SIZE(pEphPrivate),
                           pEC, pScratchBuffer);

         /* extract X component: ephPublicX = (ephPublic.x) mod order */
         gfec_GetPoint(dataR, NULL, &ephPublic, pEC);
         GFP_METHOD(pGFE)->decode(dataR, dataR, pGFE);
         ns = cpMod_BNU(dataR, elmLen, pOrder, orderLen);
         cpGFpElementPadd(dataR+ns, orderLen-ns, 0);

         cpEcGFpReleasePool(1, pEC);

         /* reduce message: msg = msg mod ordfer */
         COPY_BNU(buffMsg, BN_NUMBER(pMsg), BN_SIZE(pMsg));
         ns = cpMod_BNU(buffMsg, BN_SIZE(pMsg), pOrder, orderLen);
         ZEXPAND_BNU(buffMsg+ns, orderLen-ns, 0);

         /* compute R signature component: r = (msg + ephPublicX) mod order */
         cpModAdd_BNU(dataR, dataR, buffMsg, pOrder, orderLen, buffR);

         /* t = (r+ephPrivate) mod order */
         ZEXPAND_COPY_BNU(buffR,orderLen, BN_NUMBER(pEphPrivate),BN_SIZE(pEphPrivate));
         cpModAdd_BNU(buffR, buffR, dataR, pOrder, orderLen, buffS);

         /* check r!=0 and t!=0 */
         if(GFP_IS_ZERO(dataR, orderLen) || GFP_IS_ZERO(buffR, orderLen)) return ippStsErr;

         /* compute S signature component: S = (1+regPrivate)^1 *(ephPrivate-r*regPrivate) mod order */
         ZEXPAND_COPY_BNU(buffS,orderLen, BN_NUMBER(pRegPrivate),BN_SIZE(pRegPrivate));
         cpMontEnc_BNU_EX(buffR, dataR, orderLen, pMontR);        /* r */
         cpMontMul_BNU(buffR, buffR, buffS,  /* r*=regPrivate */
                       pMontR);
         ZEXPAND_COPY_BNU(buffS,orderLen, BN_NUMBER(pEphPrivate),BN_SIZE(pEphPrivate));
         cpModSub_BNU(buffS, buffS, buffR, pOrder, orderLen, buffR); /* k -=r */

         //cpMontInv_BNU(dataS, dataS, pMontR); /* s = (1+regPrivate)^-1 */
         gs_mont_inv(dataS, dataS, pMontR);           /* s = (1+regPrivate)^-1 */
         cpMontMul_BNU(dataS, dataS, buffS, pMontR);  /* s *= k */

         /* check s!=0 */
         if(GFP_IS_ZERO(dataS, orderLen)) return ippStsErr;

         /* signR */
         ns = orderLen;
         FIX_BNU(dataR, ns);
         BN_SIGN(pSignR) = ippBigNumPOS;
         BN_SIZE(pSignR) = ns;
         /* signS */
         ns = orderLen;
         FIX_BNU(dataS, ns);
         BN_SIGN(pSignS) = ippBigNumPOS;
         BN_SIZE(pSignS) = ns;

         return ippStsNoErr;
      }
   }
}


/*F*
//    Name: ippsGFpECVerifySM2
//
// Purpose: SM2 Signature Verification.
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == pEC
//                               NULL == pMsg
//                               NULL == pRegPublic
//                               NULL == pSignR
//                               NULL == pSignS
//                               NULL == pResult
//                               NULL == pScratchBuffer
//
//    ippStsContextMatchErr      illegal pECC->idCtx
//                               illegal pMsgDigest->idCtx
//                               illegal pRegPublic->idCtx
//                               illegal pSignR->idCtx
//                               illegal pSignS->idCtx
//
//    ippStsMessageErr           Msg < 0
//    ippStsRangeErr             SignR < 0 or SignS < 0
//
//    ippStsOutOfRangeErr        bitsize(pRegPublic) != bitsize(prime)
//
//    ippStsNoErr                no errors
//
// Parameters:
//    pMsg           pointer to the message representative to being signed
//    pRegPublic     pointer to the regular public key
//    pSignR,pSignS  pointer to the signature
//    pResult        pointer to the result: ippECValid/ippECInvalidSignature
//    pEC            pointer to the ECCP context
//    pScratchBuffer pointer to buffer (2 mul_point operation)
//
*F*/
IPPFUN(IppStatus, ippsGFpECVerifySM2,(const IppsBigNumState* pMsg,
                                      const IppsGFpECPoint* pRegPublic,
                                      const IppsBigNumState* pSignR, const IppsBigNumState* pSignS,
                                      IppECResult* pResult,
                                      IppsGFpECState* pEC,
                                      Ipp8u* pScratchBuffer))
{
   IppsGFpState*  pGF;
   gsModEngine* pGFE;

   /* EC context and buffer */
   IPP_BAD_PTR2_RET(pEC, pScratchBuffer);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET(!ECP_TEST_ID(pEC), ippStsContextMatchErr);

   pGF = ECP_GFP(pEC);
   pGFE = GFP_PMA(pGF);
   IPP_BADARG_RET(1<GFP_EXTDEGREE(pGFE), ippStsNotSupportedModeErr);

   /* test message representative */
   IPP_BAD_PTR1_RET(pMsg);
   pMsg = (IppsBigNumState*)( IPP_ALIGNED_PTR(pMsg, ALIGN_VAL) );
   IPP_BADARG_RET(!BN_VALID_ID(pMsg), ippStsContextMatchErr);
   IPP_BADARG_RET(BN_NEGATIVE(pMsg), ippStsMessageErr);

   /* test regular public key */
   IPP_BAD_PTR1_RET(pRegPublic);
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pRegPublic), ippStsContextMatchErr );
   IPP_BADARG_RET( ECP_POINT_FELEN(pRegPublic)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);

   /* test signature */
   IPP_BAD_PTR2_RET(pSignR, pSignS);
   pSignR = (IppsBigNumState*)( IPP_ALIGNED_PTR(pSignR, ALIGN_VAL) );
   pSignS = (IppsBigNumState*)( IPP_ALIGNED_PTR(pSignS, ALIGN_VAL) );
   IPP_BADARG_RET(!BN_VALID_ID(pSignR), ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pSignS), ippStsContextMatchErr);
   IPP_BADARG_RET(BN_NEGATIVE(pSignR), ippStsRangeErr);
   IPP_BADARG_RET(BN_NEGATIVE(pSignS), ippStsRangeErr);

   /* test result */
   IPP_BAD_PTR1_RET(pResult);

   {
      IppECResult vResult = ippECInvalidSignature;

      gsModEngine* pMontR = ECP_MONT_R(pEC);
      BNU_CHUNK_T* pOrder = MOD_MODULUS(pMontR);
      int orderLen = MOD_LEN(pMontR);

      /* test signature value */
      if(!cpEqu_BNU_CHUNK(BN_NUMBER(pSignR), BN_SIZE(pSignR), 0) &&
         !cpEqu_BNU_CHUNK(BN_NUMBER(pSignS), BN_SIZE(pSignS), 0) &&
         0>cpCmp_BNU(BN_NUMBER(pSignR), BN_SIZE(pSignR), pOrder, orderLen) &&
         0>cpCmp_BNU(BN_NUMBER(pSignS), BN_SIZE(pSignS), pOrder, orderLen)) {

         int elmLen = GFP_FELEN(pGFE);
         int ns;

         BNU_CHUNK_T* r = cpGFpGetPool(4, pGFE);
         BNU_CHUNK_T* s = r+orderLen;
         BNU_CHUNK_T* t = s+orderLen;
         BNU_CHUNK_T* f = t+orderLen;

         /* reduce message */
         BNU_CHUNK_T* pMsgData = BN_NUMBER(pMsg);
         BNU_CHUNK_T* pMsgBuff = BN_BUFFER(pMsg);
         int msgLen = BN_SIZE(pMsg);
         COPY_BNU(pMsgBuff, pMsgData, msgLen);
         msgLen = cpMod_BNU(pMsgBuff, msgLen, pOrder, orderLen);
         cpGFpElementPadd(pMsgBuff+msgLen, orderLen-msgLen, 0);

         /* expand signatire's components */
         cpGFpElementCopyPadd(r, orderLen, BN_NUMBER(pSignR), BN_SIZE(pSignR));
         cpGFpElementCopyPadd(s, orderLen, BN_NUMBER(pSignS), BN_SIZE(pSignS));

         /* t = (r+s) mod order */
         cpModAdd_BNU(t, r, s, pOrder, orderLen, f);

         /* P = [s]G +[t]regPublic, t = P.x */
         {
            IppsGFpECPoint P, G;
            cpEcGFpInitPoint(&P, cpEcGFpGetPool(1, pEC),0, pEC);
            cpEcGFpInitPoint(&G, ECP_G(pEC), ECP_AFFINE_POINT|ECP_FINITE_POINT, pEC);

            gfec_BasePointProduct(&P,
                                  s, orderLen, pRegPublic, t, orderLen,
                                  pEC, pScratchBuffer);

            gfec_GetPoint(t, NULL, &P, pEC);
            GFP_METHOD(pGFE)->decode(t, t, pGFE);
            ns = cpMod_BNU(t, elmLen, pOrder, orderLen);

            cpEcGFpReleasePool(1, pEC);
         }

         /* t = (msg+t) mod order */
         cpModAdd_BNU(t, t, pMsgBuff, pOrder, orderLen, f);

         if(GFP_EQ(t, r, orderLen))
            vResult = ippECValid;

         cpGFpReleasePool(4, pGFE);
      }

      *pResult = vResult;
      return ippStsNoErr;
   }
}
