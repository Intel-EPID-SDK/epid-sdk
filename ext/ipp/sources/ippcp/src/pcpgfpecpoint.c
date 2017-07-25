/*############################################################################
  # Copyright 2010-2017 Intel Corporation
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
//     Intel(R) Performance Primitives. Cryptography Primitives.
//     EC over GF(p) Operations
// 
//     Context:
//        ippsGFpECPointGetSize()
//        ippsGFpECPointInit()
// 
//        ippsGFpECSetPointAtInfinity()
//        ippsGFpECSetPoint()
//        ippsGFpECMakePoint()
//        ippsGFpECSetPointRandom()
//        ippsGFpECSetPointHash()
//        ippsGFpECGetPoint()
//        ippsGFpECCpyPoint()
// 
//        ippsGFpECCmpPoint()
//        ippsGFpECTstPoint()
//        ippsGFpECNegPoint()
//        ippsGFpECAddPoint()
//        ippsGFpECMulPoint()
// 
// 
*/
#include "owndefs.h"
#include "owncp.h"

#include "pcpgfpecstuff.h"
#include "pcphash.h"


IPPFUN(IppStatus, ippsGFpECPointGetSize,(const IppsGFpECState* pEC, int* pSizeInBytes))
{
   IPP_BAD_PTR2_RET(pEC, pSizeInBytes);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );

   {
      int elemLen = GFP_FELEN(ECP_GFP(pEC));
      *pSizeInBytes = sizeof(IppsGFpECPoint)
                     +elemLen*sizeof(BNU_CHUNK_T) /* X */
                     +elemLen*sizeof(BNU_CHUNK_T) /* Y */
                     +elemLen*sizeof(BNU_CHUNK_T);/* Z */
      return ippStsNoErr;
   }
}


IPPFUN(IppStatus, ippsGFpECPointInit,(const IppsGFpElement* pX, const IppsGFpElement* pY,
                                      IppsGFpECPoint* pPoint, IppsGFpECState* pEC))
{
   IPP_BAD_PTR2_RET(pPoint, pEC);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );

   {
      Ipp8u* ptr = (Ipp8u*)pPoint;
      int elemLen = GFP_FELEN(ECP_GFP(pEC));

      ECP_POINT_ID(pPoint) = idCtxGFPPoint;
      ECP_POINT_FLAGS(pPoint) = 0;
      ECP_POINT_FELEN(pPoint) = elemLen;
      ptr += sizeof(IppsGFpECPoint);
      ECP_POINT_DATA(pPoint) = (BNU_CHUNK_T*)(ptr);

      if(pX && pY)
         return ippsGFpECSetPoint(pX, pY, pPoint, pEC);
      else {
         gfec_SetPointAtInfinity(pPoint);
         return ippStsNoErr;
      }
   }
}


IPPFUN(IppStatus, ippsGFpECSetPointAtInfinity,(IppsGFpECPoint* pPoint, IppsGFpECState* pEC))
{
   IPP_BAD_PTR2_RET(pPoint, pEC);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pPoint), ippStsContextMatchErr );

   IPP_BADARG_RET( ECP_POINT_FELEN(pPoint)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);

   gfec_SetPointAtInfinity(pPoint);
   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsGFpECSetPoint,(const IppsGFpElement* pX, const IppsGFpElement* pY,
                                           IppsGFpECPoint* pPoint,
                                           IppsGFpECState* pEC))
{
   IPP_BAD_PTR2_RET(pPoint, pEC);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pPoint), ippStsContextMatchErr );

   IPP_BAD_PTR2_RET(pX, pY);
   IPP_BADARG_RET( !GFPE_TEST_ID(pX), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pY), ippStsContextMatchErr );

   IPP_BADARG_RET( GFPE_ROOM(pX)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( GFPE_ROOM(pY)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( ECP_POINT_FELEN(pPoint)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);

   if(gfec_SetPoint(ECP_POINT_DATA(pPoint), GFPE_DATA(pX), GFPE_DATA(pY), pEC))
      ECP_POINT_FLAGS(pPoint) = ECP_AFFINE_POINT | ECP_FINITE_POINT;
   else
      ECP_POINT_FLAGS(pPoint) = 0;
   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsGFpECGetPoint,(const IppsGFpECPoint* pPoint,
                                           IppsGFpElement* pX, IppsGFpElement* pY,
                                           IppsGFpECState* pEC))
{
   IPP_BAD_PTR2_RET(pPoint, pEC);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pPoint), ippStsContextMatchErr );

   ///IPP_BADARG_RET( !IS_ECP_FINITE_POINT(pPoint), ippStsPointAtInfinity);

   IPP_BADARG_RET( pX && !GFPE_TEST_ID(pX), ippStsContextMatchErr );
   IPP_BADARG_RET( pY && !GFPE_TEST_ID(pY), ippStsContextMatchErr );

   IPP_BADARG_RET( pX && GFPE_ROOM(pX)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( pY && GFPE_ROOM(pY)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( ECP_POINT_FELEN(pPoint)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);

   gfec_GetPoint((pX)? GFPE_DATA(pX):NULL, (pY)? GFPE_DATA(pY):NULL, pPoint, pEC);
   return ippStsNoErr;
}


IPPFUN(IppStatus, ippsGFpECMakePoint,(const IppsGFpElement* pX, IppsGFpECPoint* pPoint, IppsGFpECState* pEC))
{
   IPP_BAD_PTR3_RET(pX, pPoint, pEC);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFP_IS_BASIC(ECP_GFP(pEC)), ippStsBadArgErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pX), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pPoint), ippStsContextMatchErr );

   IPP_BADARG_RET( GFPE_ROOM(pX)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( ECP_POINT_FELEN(pPoint)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);

   return gfec_MakePoint(pPoint, GFPE_DATA(pX), pEC)? ippStsNoErr : ippStsQuadraticNonResidueErr;
}


IPPFUN(IppStatus, ippsGFpECSetPointRandom,(IppsGFpECPoint* pPoint, IppsGFpECState* pEC,
                                           IppBitSupplier rndFunc, void* pRndParam,
                                           Ipp8u* pScratchBuffer))
{
   IPP_BAD_PTR3_RET(pPoint, pEC, pScratchBuffer);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pPoint), ippStsContextMatchErr );

   IPP_BADARG_RET( ECP_POINT_FELEN(pPoint)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);

   IPP_BAD_PTR2_RET(rndFunc, pRndParam);

   {
      IppsGFpState* pGF = ECP_GFP(pEC);

      if( GFP_IS_BASIC(pGF) ) {
         BNU_CHUNK_T* pElm = cpGFpGetPool(1, pGF);

         do { /* get random X */
            cpGFpRand(pElm, pGF, rndFunc, pRndParam);
         } while( !gfec_MakePoint(pPoint, pElm, pEC) );

         cpGFpReleasePool(1, pGF);

         /* R = [cofactor]R */
         gfec_MulPoint(pPoint, pPoint, ECP_COFACTOR(pEC), GFP_FELEN(pGF), pEC, pScratchBuffer);

         return ippStsNoErr;
      }

      else {
         /* number of bits and dwords being generated */
         int generatedBits = ECP_ORDBITSIZE(pEC) + GF_RAND_ADD_BITS;
         int generatedLen = BITS_BNU_CHUNK(generatedBits);

         /* allocate random exponent */
         int poolElements = (generatedLen + GFP_PELEN(pGF) -1) / GFP_PELEN(pGF);
         BNU_CHUNK_T* pExp = cpGFpGetPool(poolElements, pGF);
         int nsE;

         /* setup copy of the base point */
         IppsGFpECPoint G;
         cpEcGFpInitPoint(&G, ECP_G(pEC),ECP_AFFINE_POINT|ECP_FINITE_POINT, pEC);

         /* get random bits */
         rndFunc((Ipp32u*)pExp, generatedBits, pRndParam);
         /* reduce with respect to order value */
         //nsE = cpMod_BNU(pExp, generatedLen, ECP_R(pEC), BITS_BNU_CHUNK(ECP_ORDBITSIZE(pEC)));
         nsE = cpMod_BNU(pExp, generatedLen, MNT_MODULUS(ECP_MONT_R(pEC)), BITS_BNU_CHUNK(ECP_ORDBITSIZE(pEC)));

         /* compute random point */
         gfec_MulPoint(pPoint, &G, pExp, nsE, pEC, pScratchBuffer);

         cpGFpReleasePool(poolElements, pGF);

         return ippStsNoErr;
      }
   }
}



IPPFUN(IppStatus, ippsGFpECCpyPoint,(const IppsGFpECPoint* pA,
                                           IppsGFpECPoint* pR,
                                           IppsGFpECState* pEC))
{
   IPP_BAD_PTR3_RET(pA, pR, pEC);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pA), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pR), ippStsContextMatchErr );

   IPP_BADARG_RET( ECP_POINT_FELEN(pA)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( ECP_POINT_FELEN(pR)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);

   gfec_CopyPoint(pR, pA, GFP_FELEN(ECP_GFP(pEC)));
   return ippStsNoErr;
}


IPPFUN(IppStatus, ippsGFpECCmpPoint,(const IppsGFpECPoint* pP, const IppsGFpECPoint* pQ,
                                           IppECResult* pResult,
                                           IppsGFpECState* pEC))
{
   IPP_BAD_PTR4_RET(pP, pQ, pResult, pEC);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pP), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pQ), ippStsContextMatchErr );

   IPP_BADARG_RET( ECP_POINT_FELEN(pP)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( ECP_POINT_FELEN(pQ)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);

   *pResult = gfec_ComparePoint(pP, pQ, pEC)? ippECPointIsEqual : ippECPointIsNotEqual;
   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsGFpECTstPoint,(const IppsGFpECPoint* pP,
                                     IppECResult* pResult,
                                     IppsGFpECState* pEC))
{
   IPP_BAD_PTR3_RET(pP, pResult, pEC);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pP), ippStsContextMatchErr );

   IPP_BADARG_RET( ECP_POINT_FELEN(pP)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);

   if( gfec_IsPointAtInfinity(pP) )
      *pResult = ippECPointIsAtInfinite;
   else if( !gfec_IsPointOnCurve(pP, pEC) )
      *pResult = ippECPointIsNotValid;
   else
      *pResult = ippECValid;

   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsGFpECTstPointInSubgroup,(const IppsGFpECPoint* pP,
                                               IppECResult* pResult,
                                               IppsGFpECState* pEC,
                                               Ipp8u* pScratchBuffer))
{
   IPP_BAD_PTR4_RET(pP, pResult, pEC, pScratchBuffer);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pP), ippStsContextMatchErr );

   IPP_BADARG_RET( ECP_POINT_FELEN(pP)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);

   {
      IppECResult tstResult;
      ippsGFpECTstPoint(pP, &tstResult, pEC);

      if(ippECValid==tstResult) {
         IppsGFpECPoint T;
         cpEcGFpInitPoint(&T, cpEcGFpGetPool(1, pEC),0, pEC);

         gfec_MulPoint(&T, pP, MNT_MODULUS(ECP_MONT_R(pEC)), BITS_BNU_CHUNK(ECP_ORDBITSIZE(pEC)), pEC, pScratchBuffer);
         tstResult = gfec_IsPointAtInfinity(&T)? ippECValid : ippECPointOutOfGroup;

         cpEcGFpReleasePool(1, pEC);
      }
      *pResult = tstResult;

      return ippStsNoErr;
   }
}


IPPFUN(IppStatus, ippsGFpECNegPoint,(const IppsGFpECPoint* pP,
                                           IppsGFpECPoint* pR,
                                           IppsGFpECState* pEC))
{
   IPP_BAD_PTR3_RET(pP, pR, pEC);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pP), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pR), ippStsContextMatchErr );

   IPP_BADARG_RET( ECP_POINT_FELEN(pP)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( ECP_POINT_FELEN(pR)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);

   gfec_NegPoint(pR, pP, pEC);
   return ippStsNoErr;
}


IPPFUN(IppStatus, ippsGFpECAddPoint,(const IppsGFpECPoint* pP, const IppsGFpECPoint* pQ, IppsGFpECPoint* pR,
                  IppsGFpECState* pEC))
{
   IPP_BAD_PTR4_RET(pP, pQ, pR, pEC);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pP), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pQ), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pR), ippStsContextMatchErr );

   IPP_BADARG_RET( ECP_POINT_FELEN(pP)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( ECP_POINT_FELEN(pQ)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( ECP_POINT_FELEN(pR)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);

   if(pP==pQ)
      gfec_DblPoint(pR, pP, pEC);
   else
      gfec_AddPoint(pR, pP, pQ, pEC);
   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsGFpECMulPoint,(const IppsGFpECPoint* pP,
                                     const IppsBigNumState* pN,
                                     IppsGFpECPoint* pR,
                                     IppsGFpECState* pEC,
                                     Ipp8u* pScratchBuffer))
{
   IPP_BAD_PTR4_RET(pP, pR, pEC, pScratchBuffer);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pP), ippStsContextMatchErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pR), ippStsContextMatchErr );

   IPP_BAD_PTR1_RET(pN);
   pN = (IppsBigNumState*)( IPP_ALIGNED_PTR(pN, BN_ALIGNMENT) );
   IPP_BADARG_RET(!BN_VALID_ID(pN), ippStsContextMatchErr );
   IPP_BADARG_RET( BN_NEGATIVE(pN), ippStsBadArgErr );
   IPP_BADARG_RET(BN_SIZE(pN)>2*GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);

   IPP_BADARG_RET( ECP_POINT_FELEN(pP)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( ECP_POINT_FELEN(pR)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);

   gfec_MulPoint(pR, pP, BN_NUMBER(pN), BN_SIZE(pN), pEC, pScratchBuffer);
   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsGFpECSetPointHash,(Ipp32u hdr, const Ipp8u* pMsg, int msgLen, IppsGFpECPoint* pPoint,
                                         IppsGFpECState* pEC, IppHashAlgId hashID,
                                         Ipp8u* pScratchBuffer))
{
   /* get algorithm id */
   hashID = cpValidHashAlg(hashID);
   IPP_BADARG_RET(ippHashAlg_Unknown==hashID, ippStsNotSupportedModeErr);

   /* test message length */
   IPP_BADARG_RET((msgLen<0), ippStsLengthErr);
   /* test message pointer */
   IPP_BADARG_RET((msgLen && !pMsg), ippStsNullPtrErr);

   IPP_BAD_PTR3_RET(pPoint, pEC, pScratchBuffer);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFP_IS_BASIC(ECP_GFP(pEC)), ippStsBadArgErr );
   IPP_BADARG_RET( !ECP_POINT_TEST_ID(pPoint), ippStsContextMatchErr );

   IPP_BADARG_RET( ECP_POINT_FELEN(pPoint)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);

   {
      IppsGFpState* pGF = ECP_GFP(pEC);
      int elemLen = GFP_FELEN(pGF);
      BNU_CHUNK_T* pModulus = GFP_MODULUS(pGF);

      Ipp8u md[IPP_SHA512_DIGEST_BITSIZE/BYTESIZE];
      int hashLen = cpHashAlgAttr[hashID].hashSize;
      BNU_CHUNK_T hashVal[BITS_BNU_CHUNK(IPP_SHA512_DIGEST_BITSIZE)+1];
      int hashValLen;

      IppsHashState hashCtx;
      ippsHashInit(&hashCtx, hashID);

      {
         BNU_CHUNK_T* pPoolElm = cpGFpGetPool(1, pGF);

         /* convert hdr => hdrStr */
         BNU_CHUNK_T locHdr = (BNU_CHUNK_T)hdr;
         Ipp8u hdrOctStr[sizeof(hdr/*locHdr*/)];
         cpToOctStr_BNU(hdrOctStr, sizeof(hdrOctStr), &locHdr, 1);

         /* compute md = hash(hrd||msg) */
         ippsHashUpdate(hdrOctStr, sizeof(hdrOctStr), &hashCtx);
         ippsHashUpdate(pMsg, msgLen, &hashCtx);
         ippsHashFinal(md, &hashCtx);

         /* convert hash into the integer */
         hashValLen = cpFromOctStr_BNU(hashVal, md, hashLen);
         hashValLen = cpMod_BNU(hashVal, hashValLen, pModulus, elemLen);
         cpGFpSet(pPoolElm, hashVal, hashValLen, pGF);

         if( gfec_MakePoint(pPoint, pPoolElm, pEC)) {
            /* set y-coordinate of the point (positive or negative) */
            BNU_CHUNK_T* pY = ECP_POINT_Y(pPoint);
            if(pY[0] & 1)
               cpGFpNeg(pY, pY, pGF);

            /* update point if cofactor>1 */
            gfec_MulPoint(pPoint, pPoint, ECP_COFACTOR(pEC), GFP_FELEN(pGF), pEC, pScratchBuffer);

            cpGFpReleasePool(1, pGF);
            return ippStsNoErr;
         }
      }

      cpGFpReleasePool(1, pGF);
      return ippStsQuadraticNonResidueErr;
   }
}
