/*############################################################################
  # Copyright 2003-2017 Intel Corporation
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
//     EC over Prime Finite Field (setup/retrieve domain parameters)
// 
//  Contents:
//     ippsECCPSet()
//     ippsECCPSetStd()
//     ippsECCPSetStd128r1()
//     ippsECCPSetStd128r2()
//     ippsECCPSetStd192r1()
//     ippsECCPSetStd224r1()
//     ippsECCPSetStd256r1()
//     ippsECCPSetStd384r1()
//     ippsECCPSetStd521r1()
//     ippsECCPSetStdSM2()
// 
//     ippsECCPGet()
//     ippsECCPGetBitSizeOrder()
// 
// 
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpeccp.h"


/*F*
//    Name: ippsECCPSet
//
// Purpose: Set EC Domain Parameters.
//
// Returns:                Reason:
//    ippStsNullPtrErr        NULL == pPrime
//                            NULL == pA
//                            NULL == pB
//                            NULL == pGX
//                            NULL == pGY
//                            NULL == pOrder
//                            NULL == pECC
//
//    ippStsContextMatchErr   illegal pPrime->idCtx
//                            illegal pA->idCtx
//                            illegal pB->idCtx
//                            illegal pGX->idCtx
//                            illegal pGY->idCtx
//                            illegal pOrder->idCtx
//                            illegal pECC->idCtx
//
//    ippStsRangeErr          not enough room for:
//                            pPrime
//                            pA, pB,
//                            pGX,pGY
//                            pOrder
//
//    ippStsRangeErr          0>= cofactor
//
//    ippStsNoErr             no errors
//
// Parameters:
//    pPrime   pointer to the prime (specify FG(p))
//    pA       pointer to the A coefficient of EC equation
//    pB       pointer to the B coefficient of EC equation
//    pGX,pGY  pointer to the Base Point (x and y coordinates) of EC
//    pOrder   pointer to the Base Point order
//    cofactor cofactor value
//    pECC     pointer to the ECC context
//
*F*/
IppStatus ECCPSetDP(const IppsGFpMethod* method,
                        int pLen, const BNU_CHUNK_T* pP,
                        int aLen, const BNU_CHUNK_T* pA,
                        int bLen, const BNU_CHUNK_T* pB,
                        int xLen, const BNU_CHUNK_T* pX,
                        int yLen, const BNU_CHUNK_T* pY,
                        int rLen, const BNU_CHUNK_T* pR,
                        BNU_CHUNK_T h,
                        IppsGFpECState* pEC)
{
   IPP_BADARG_RET(!ECP_TEST_ID(pEC), ippStsContextMatchErr);

   {
      IppsGFpState *   pGF = ECP_GFP(pEC);

      IppStatus sts;
      IppsBigNumState P, H;
      //int primeBitSize = GFP_FEBITLEN(pGF);
      cpConstructBN(&P, pLen, (BNU_CHUNK_T*)pP, NULL);
      sts = cpGFpSetGFp(&P, method, pGF);

      if(ippStsNoErr==sts) {
         do {
            int elemLen = GFP_FELEN(pGF);
            IppsGFpElement elmA, elmB;

            /* convert A ans B coeffs into GF elements */
            cpGFpElementConstruct(&elmA, cpGFpGetPool(1, pGF), elemLen);
            cpGFpElementConstruct(&elmB, cpGFpGetPool(1, pGF), elemLen);
            sts = ippsGFpSetElement((Ipp32u*)pA, BITS2WORD32_SIZE(BITSIZE_BNU(pA,aLen)), &elmA, pGF);
            if(ippStsNoErr!=sts) break;
            sts = ippsGFpSetElement((Ipp32u*)pB, BITS2WORD32_SIZE(BITSIZE_BNU(pB,bLen)), &elmB, pGF);
            if(ippStsNoErr!=sts) break;
            /* and set EC */
            sts = ippsGFpECSet(&elmA, &elmB, pEC);
            if(ippStsNoErr!=sts) break;

            /* convert GX ans GY coeffs into GF elements */
            cpConstructBN(&P, rLen, (BNU_CHUNK_T*)pR, NULL);
            cpConstructBN(&H, 1, &h, NULL);
            sts = ippsGFpSetElement((Ipp32u*)pX, BITS2WORD32_SIZE(BITSIZE_BNU(pX,xLen)), &elmA, pGF);
            if(ippStsNoErr!=sts) break;
            sts = ippsGFpSetElement((Ipp32u*)pY, BITS2WORD32_SIZE(BITSIZE_BNU(pY,yLen)), &elmB, pGF);
            if(ippStsNoErr!=sts) break;
            /* and init EC subgroup */
            sts = ippsGFpECSetSubgroup(&elmA, &elmB, &P, &H, pEC);
         } while(0);

         cpGFpReleasePool(2, pGF);
      }

      return sts;
   }
}

IPPFUN(IppStatus, ippsECCPSet, (const IppsBigNumState* pPrime,
                                const IppsBigNumState* pA, const IppsBigNumState* pB,
                                const IppsBigNumState* pGX,const IppsBigNumState* pGY,
                                const IppsBigNumState* pOrder, int cofactor,
                                IppsECCPState* pEC))
{
   /* test pEC */
   IPP_BAD_PTR1_RET(pEC);
   /* use aligned EC context */
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET(!ECP_TEST_ID(pEC), ippStsContextMatchErr);

   /* test pPrime */
   IPP_BAD_PTR1_RET(pPrime);
   pPrime = (IppsBigNumState*)( IPP_ALIGNED_PTR(pPrime, BN_ALIGNMENT) );
   IPP_BADARG_RET(!BN_VALID_ID(pPrime), ippStsContextMatchErr);
   IPP_BADARG_RET((cpBN_bitsize(pPrime)>GFP_FEBITLEN(ECP_GFP(pEC))), ippStsRangeErr);

   /* test pA and pB */
   IPP_BAD_PTR2_RET(pA,pB);
   pA = (IppsBigNumState*)( IPP_ALIGNED_PTR(pA, ALIGN_VAL) );
   pB = (IppsBigNumState*)( IPP_ALIGNED_PTR(pB, ALIGN_VAL) );
   IPP_BADARG_RET(!BN_VALID_ID(pA), ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pB), ippStsContextMatchErr);
   //IPP_BADARG_RET((cpBN_bitsize(pA)>GFP_FEBITLEN(ECP_GFP(pEC))), ippStsRangeErr);
   //IPP_BADARG_RET((cpBN_bitsize(pB)>GFP_FEBITLEN(ECP_GFP(pEC))), ippStsRangeErr);
   IPP_BADARG_RET(BN_NEGATIVE(pA) || 0<=cpBN_cmp(pA,pPrime), ippStsRangeErr);
   IPP_BADARG_RET(BN_NEGATIVE(pB) || 0<=cpBN_cmp(pB,pPrime), ippStsRangeErr);

   /* test pG and pGorder pointers */
   IPP_BAD_PTR3_RET(pGX,pGY, pOrder);
   pGX    = (IppsBigNumState*)( IPP_ALIGNED_PTR(pGX,    ALIGN_VAL) );
   pGY    = (IppsBigNumState*)( IPP_ALIGNED_PTR(pGY,    ALIGN_VAL) );
   pOrder = (IppsBigNumState*)( IPP_ALIGNED_PTR(pOrder, ALIGN_VAL) );
   IPP_BADARG_RET(!BN_VALID_ID(pGX),    ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pGY),    ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pOrder), ippStsContextMatchErr);
   //IPP_BADARG_RET((cpBN_bitsize(pGX)>GFP_FEBITLEN(ECP_GFP(pEC))),    ippStsRangeErr);
   //IPP_BADARG_RET((cpBN_bitsize(pGY)>GFP_FEBITLEN(ECP_GFP(pEC))),    ippStsRangeErr);
   IPP_BADARG_RET(BN_NEGATIVE(pGX) || 0<=cpBN_cmp(pGX,pPrime), ippStsRangeErr);
   IPP_BADARG_RET(BN_NEGATIVE(pGY) || 0<=cpBN_cmp(pGY,pPrime), ippStsRangeErr);
   IPP_BADARG_RET((cpBN_bitsize(pOrder)>ECP_ORDBITSIZE(pEC)), ippStsRangeErr);

   /* test cofactor */
   IPP_BADARG_RET(!(0<cofactor), ippStsRangeErr);

   return ECCPSetDP(ippsGFpMethod_pArb(),
                        BN_SIZE(pPrime), BN_NUMBER(pPrime),
                        BN_SIZE(pA), BN_NUMBER(pA),
                        BN_SIZE(pB), BN_NUMBER(pB),
                        BN_SIZE(pGX), BN_NUMBER(pGX),
                        BN_SIZE(pGY), BN_NUMBER(pGY),
                        BN_SIZE(pOrder), BN_NUMBER(pOrder),
                        (BNU_CHUNK_T)cofactor,
                        pEC);
}

/*F*
//    Name: ippsECCPGet
//
// Purpose: Retrieve ECC Domain Parameter.
//
// Returns:                Reason:
//    ippStsNullPtrErr        NULL == pPrime
//                            NULL == pA
//                            NULL == pB
//                            NULL == pGX
//                            NULL == pGY
//                            NULL == pOrder
//                            NULL == cofactor
//                            NULL == pECC
//
//    ippStsContextMatchErr   illegal pPrime->idCtx
//                            illegal pA->idCtx
//                            illegal pB->idCtx
//                            illegal pGX->idCtx
//                            illegal pGY->idCtx
//                            illegal pOrder->idCtx
//                            illegal pECC->idCtx
//
//    ippStsRangeErr          not enough room for:
//                            pPrime
//                            pA, pB,
//                            pGX,pGY
//                            pOrder
//
//    ippStsNoErr             no errors
//
// Parameters:
//    pPrime   pointer to the retrieval prime (specify FG(p))
//    pA       pointer to the retrieval A coefficient of EC equation
//    pB       pointer to the retrieval B coefficient of EC equation
//    pGX,pGY  pointer to the retrieval Base Point (x and y coordinates) of EC
//    pOrder   pointer to the retrieval Base Point order
//    cofactor pointer to the retrieval cofactor value
//    pECC     pointer to the ECC context
//
*F*/
IPPFUN(IppStatus, ippsECCPGet, (IppsBigNumState* pPrime,
                                IppsBigNumState* pA, IppsBigNumState* pB,
                                IppsBigNumState* pGX,IppsBigNumState* pGY,IppsBigNumState* pOrder,
                                int* cofactor,
                                IppsECCPState* pEC))
{
   /* test pECC */
   IPP_BAD_PTR1_RET(pEC);
   /* use aligned EC context */
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET(!ECP_TEST_ID(pEC), ippStsContextMatchErr);

   /* test pPrime */
   IPP_BAD_PTR1_RET(pPrime);
   pPrime = (IppsBigNumState*)( IPP_ALIGNED_PTR(pPrime, ALIGN_VAL) );
   IPP_BADARG_RET(!BN_VALID_ID(pPrime), ippStsContextMatchErr);
   IPP_BADARG_RET(BN_ROOM(pPrime)<GFP_FELEN(ECP_GFP(pEC)), ippStsRangeErr);

   /* test pA and pB */
   IPP_BAD_PTR2_RET(pA,pB);
   pA = (IppsBigNumState*)( IPP_ALIGNED_PTR(pA, ALIGN_VAL) );
   pB = (IppsBigNumState*)( IPP_ALIGNED_PTR(pB, ALIGN_VAL) );
   IPP_BADARG_RET(!BN_VALID_ID(pA), ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pB), ippStsContextMatchErr);
   IPP_BADARG_RET(BN_ROOM(pA)<GFP_FELEN(ECP_GFP(pEC)), ippStsRangeErr);
   IPP_BADARG_RET(BN_ROOM(pB)<GFP_FELEN(ECP_GFP(pEC)), ippStsRangeErr);

   /* test pG and pGorder pointers */
   IPP_BAD_PTR3_RET(pGX,pGY, pOrder);
   pGX   = (IppsBigNumState*)( IPP_ALIGNED_PTR(pGX,   ALIGN_VAL) );
   pGY   = (IppsBigNumState*)( IPP_ALIGNED_PTR(pGY,   ALIGN_VAL) );
   pOrder= (IppsBigNumState*)( IPP_ALIGNED_PTR(pOrder,ALIGN_VAL) );
   IPP_BADARG_RET(!BN_VALID_ID(pGX),    ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pGY),    ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pOrder), ippStsContextMatchErr);
   IPP_BADARG_RET(BN_ROOM(pGX)<GFP_FELEN(ECP_GFP(pEC)),    ippStsRangeErr);
   IPP_BADARG_RET(BN_ROOM(pGY)<GFP_FELEN(ECP_GFP(pEC)),    ippStsRangeErr);
   IPP_BADARG_RET((BN_ROOM(pOrder)*BITSIZE(BNU_CHUNK_T)<ECP_ORDBITSIZE(pEC)), ippStsRangeErr);

   /* test cofactor */
   IPP_BAD_PTR1_RET(cofactor);

   {
      IppsGFpState* pGF = ECP_GFP(pEC);
      gfdecode  decode = pGF->decode;  /* gf decode method  */
      BNU_CHUNK_T* tmp = cpGFpGetPool(1, pGF);

      /* retrieve EC parameter */
      ippsSet_BN(ippBigNumPOS, GFP_FELEN32(pGF), (Ipp32u*)GFP_MODULUS(pGF), pPrime);

      decode(tmp, ECP_A(pEC), pGF);
      ippsSet_BN(ippBigNumPOS, GFP_FELEN32(pGF), (Ipp32u*)tmp, pA);
      decode(tmp, ECP_B(pEC), pGF);
      ippsSet_BN(ippBigNumPOS, GFP_FELEN32(pGF), (Ipp32u*)tmp, pB);

      decode(tmp, ECP_G(pEC), pGF);
      ippsSet_BN(ippBigNumPOS, GFP_FELEN32(pGF), (Ipp32u*)tmp, pGX);
      decode(tmp, ECP_G(pEC)+GFP_FELEN(pGF), pGF);
      ippsSet_BN(ippBigNumPOS, GFP_FELEN32(pGF), (Ipp32u*)tmp, pGY);

      {
         IppsMontState* pR = ECP_MONT_R(pEC);
         ippsSet_BN(ippBigNumPOS, MNT_SIZE(pR)*sizeof(BNU_CHUNK_T)/sizeof(Ipp32u), (Ipp32u*)MNT_MODULUS(pR), pOrder);
      }

      *cofactor = (int)ECP_COFACTOR(pEC)[0];

      cpGFpReleasePool(1, pGF);
      return ippStsNoErr;
   }
}


/*F*
//    Name: ippsECCPGetOrderBitSize
//
// Purpose: Retrieve size of Pase Point Order (in bits).
//
// Returns:                Reason:
//    ippStsNullPtrErr        NULL == pECC
//                            NULL == pBitSize
//
//    ippStsContextMatchErr   illegal pECC->idCtx
//
//    ippStsNoErr             no errors
//
// Parameters:
//    pBitSize pointer to the size of base point order
//    pECC     pointer to the ECC context
//
*F*/
IPPFUN(IppStatus, ippsECCPGetOrderBitSize,(int* pBitSize, IppsECCPState* pEC))
{
   /* test pECC */
   IPP_BAD_PTR1_RET(pEC);
   /* use aligned EC context */
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET(!ECP_TEST_ID(pEC), ippStsContextMatchErr);

   /* test pBitSize*/
   IPP_BAD_PTR1_RET(pBitSize);

   *pBitSize = ECP_ORDBITSIZE(pEC);
   return ippStsNoErr;
}
