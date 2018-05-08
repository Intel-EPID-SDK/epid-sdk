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
//     Intel(R) Performance Primitives. Cryptography Primitives.
//     Operations over GF(p).
// 
//     Context:
//        ippsGFpGetSize()
//        ippsGFpInitArbitrary()
//        ippsGFpInitFixed()
//        ippsGFpInit()
// 
//        ippsGFpElementGetSize()
//        ippsGFpElementInit()
// 
//        ippsGFpSetElement()
//        ippsGFpSetElementRegular()
//        ippsGFpSetElementOctString()
//        ippsGFpSetElementRandom()
//        ippsGFpSetElementHash()
//        ippsGFpSetElementHash_rmf
//        ippsGFpCpyElement()
//        ippsGFpGetElement()
//        ippsGFpGetElementOctString()
// 
//        ippsGFpCmpElement()
//        ippsGFpIsZeroElement()
//        ippsGFpIsUnityElement()
// 
//        ippsGFpSetPolyTerm()
//        ippsGFpGetPolyTerm()
// 
//        ippsGFpConj()
//        ippsGFpNeg()
//        ippsGFpInv()
//        ippsGFpSqrt()
//        ippsGFpAdd()
//        ippsGFpSub()
//        ippsGFpMul()
//        ippsGFpSqr()
//        ippsGFpExp()
//        ippsGFpMultiExp()
// 
//        ippsGFpAdd_GFpE()
//        ippsGFpSub_GFpE()
//        ippsGFpMul_GFpE()
// 
// 
*/
#include "owndefs.h"
#include "owncp.h"

#include "pcpgfpstuff.h"
#include "pcpgfpxstuff.h"
#include "pcphash.h"
#include "pcphash_rmf.h"
#include "pcptool.h"

//gres: temporary excluded: #include <assert.h>


/*
// size of GFp engine context (Montgomery)
*/
int cpGFpGetSize(int feBitSize, int peBitSize, int numpe)
{
   int ctxSize = 0;
   int elemLen = BITS_BNU_CHUNK(feBitSize);
   int pelmLen = BITS_BNU_CHUNK(peBitSize);
   
   /* size of GFp engine */
   ctxSize = sizeof(gsModEngine)
            + elemLen*sizeof(BNU_CHUNK_T)    /* modulus  */
            + elemLen*sizeof(BNU_CHUNK_T)    /* mont_R   */
            + elemLen*sizeof(BNU_CHUNK_T)    /* mont_R^2 */
            + elemLen*sizeof(BNU_CHUNK_T)    /* half of modulus */
            + elemLen*sizeof(BNU_CHUNK_T)    /* quadratic non-residue */
            + pelmLen*sizeof(BNU_CHUNK_T)*numpe; /* pool */

   ctxSize += sizeof(IppsGFpState);   /* size of IppsGFPState */
   return ctxSize;
}

IPPFUN(IppStatus, ippsGFpGetSize,(int feBitSize, int* pSize))
{
   IPP_BAD_PTR1_RET(pSize);
   IPP_BADARG_RET((feBitSize < 2) || (feBitSize > GFP_MAX_BITSIZE), ippStsSizeErr);

   *pSize = cpGFpGetSize(feBitSize, feBitSize+BITSIZE(BNU_CHUNK_T), GFP_POOL_SIZE)
          + GFP_ALIGNMENT;
   return ippStsNoErr;
}


/*
// init GFp engine context (Montgomery)
*/
static void cpGFEInit(gsModEngine* pGFE, int modulusBitSize, int peBitSize, int numpe)
{
   int modLen  = BITS_BNU_CHUNK(modulusBitSize);
   int pelmLen = BITS_BNU_CHUNK(peBitSize);

   Ipp8u* ptr = (Ipp8u*)pGFE;

   /* clear whole context */
   PaddBlock(0, ptr, sizeof(gsModEngine));
   ptr += sizeof(gsModEngine);

   GFP_PARENT(pGFE)    = NULL;
   GFP_EXTDEGREE(pGFE) = 1;
   GFP_FEBITLEN(pGFE)  = modulusBitSize;
   GFP_FELEN(pGFE)     = modLen;
   GFP_FELEN32(pGFE)   = BITS2WORD32_SIZE(modulusBitSize);
   GFP_PELEN(pGFE)     = pelmLen;
 //GFP_METHOD(pGFE)    = method;
   GFP_MODULUS(pGFE)   = (BNU_CHUNK_T*)(ptr);   ptr += modLen*sizeof(BNU_CHUNK_T);
   GFP_MNT_R(pGFE)     = (BNU_CHUNK_T*)(ptr);   ptr += modLen*sizeof(BNU_CHUNK_T);
   GFP_MNT_RR(pGFE)    = (BNU_CHUNK_T*)(ptr);   ptr += modLen*sizeof(BNU_CHUNK_T);
   GFP_HMODULUS(pGFE)  = (BNU_CHUNK_T*)(ptr);   ptr += modLen*sizeof(BNU_CHUNK_T);
   GFP_QNR(pGFE)       = (BNU_CHUNK_T*)(ptr);   ptr += modLen*sizeof(BNU_CHUNK_T);
   GFP_POOL(pGFE)      = (BNU_CHUNK_T*)(ptr);/* ptr += modLen*sizeof(BNU_CHUNK_T);*/
   GFP_MAXPOOL(pGFE)   = numpe;
   GFP_USEDPOOL(pGFE)  = 0;

   cpGFpElementPadd(GFP_MODULUS(pGFE), modLen, 0);
   cpGFpElementPadd(GFP_MNT_R(pGFE), modLen, 0);
   cpGFpElementPadd(GFP_MNT_RR(pGFE), modLen, 0);
   cpGFpElementPadd(GFP_HMODULUS(pGFE), modLen, 0);
   cpGFpElementPadd(GFP_QNR(pGFE), modLen, 0);
}

static void cpGFEqnr(gsModEngine* pGFE)
{
   BNU_CHUNK_T* pQnr = GFP_QNR(pGFE);

   int elemLen = GFP_FELEN(pGFE);
   BNU_CHUNK_T* e = cpGFpGetPool(3, pGFE);
   BNU_CHUNK_T* t = e+elemLen;
   BNU_CHUNK_T* p1 = t+elemLen;
   //gres: temporary excluded: assert(NULL!=e);

   cpGFpElementCopyPadd(p1, elemLen, GFP_MNT_R(pGFE), elemLen);

   /* (modulus-1)/2 */
   cpLSR_BNU(e, GFP_MODULUS(pGFE), elemLen, 1);

   /* find a non-square g, where g^{(modulus-1)/2} = -1 */
   cpGFpElementCopy(pQnr, p1, elemLen);
   do {
      cpGFpAdd(pQnr, pQnr, p1, pGFE);
      cpGFpExp(t, pQnr, e, elemLen, pGFE);
      cpGFpNeg(t, t, pGFE);
   } while( !GFP_EQ(p1, t, elemLen) );

   cpGFpReleasePool(3, pGFE);
}

static void cpGFESet(gsModEngine* pGFE, const BNU_CHUNK_T* pPrime, int primeBitSize, const gsModMethod* method)
{
   int primeLen = BITS_BNU_CHUNK(primeBitSize);

   /* arithmetic methods */
   GFP_METHOD(pGFE) = method;

   /* store modulus */
   COPY_BNU(GFP_MODULUS(pGFE), pPrime, primeLen);

   /* montgomery factor */
   GFP_MNT_FACTOR(pGFE) = gsMontFactor(GFP_MODULUS(pGFE)[0]);

   /* montgomery identity (R) */
   ZEXPAND_BNU(GFP_MNT_R(pGFE), 0, primeLen);
   GFP_MNT_R(pGFE)[primeLen] = 1;
   cpMod_BNU(GFP_MNT_R(pGFE), primeLen+1, GFP_MODULUS(pGFE), primeLen);

   /* montgomery domain converter (RR) */
   ZEXPAND_BNU(GFP_MNT_RR(pGFE), 0, primeLen);
   COPY_BNU(GFP_MNT_RR(pGFE)+primeLen, GFP_MNT_R(pGFE), primeLen);
   cpMod_BNU(GFP_MNT_RR(pGFE), 2*primeLen, GFP_MODULUS(pGFE), primeLen);

   /* half of modulus */
   cpLSR_BNU(GFP_HMODULUS(pGFE), GFP_MODULUS(pGFE), primeLen, 1);

   /* set qnr value */
   cpGFEqnr(pGFE);
}

IppStatus cpGFpInitGFp(int primeBitSize, IppsGFpState* pGF)
{
   IPP_BADARG_RET((primeBitSize< IPP_MIN_GF_BITSIZE) || (primeBitSize> IPP_MAX_GF_BITSIZE), ippStsSizeErr);
   IPP_BAD_PTR1_RET(pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );

   {
      Ipp8u* ptr = (Ipp8u*)pGF;

      GFP_ID(pGF)      = idCtxGFP;
      GFP_PMA(pGF) = (gsModEngine*)(ptr+sizeof(IppsGFpState));
      cpGFEInit(GFP_PMA(pGF), primeBitSize, primeBitSize+BITSIZE(BNU_CHUNK_T), GFP_POOL_SIZE);

      return ippStsNoErr;
   }
}

IppStatus cpGFpSetGFp(const BNU_CHUNK_T* pPrime, int primeBitSize, const IppsGFpMethod* method, IppsGFpState* pGF)
{
   cpGFESet(GFP_PMA(pGF), pPrime, primeBitSize, method->arith);
   return ippStsNoErr;
}

/*F*
// Name: ippsGFpInitFixed
//
// Purpose: initializes prime finite field GF(p)
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == method
//                               NULL == pGF
//
//    ippStsBadArgErr            method != ippsGFpMethod_pXXX() any fixed prime method
//                               primeBitSize != sizeof modulus defined by fixed method
//
//    ippStsNoErr                no error
//
// Parameters:
//    primeBitSize   length of prime in bits
//    method         pointer to the basic arithmetic metods
//    pGF            pointer to Finite Field context is being initialized
*F*/
IPPFUN(IppStatus, ippsGFpInitFixed,(int primeBitSize, const IppsGFpMethod* method, IppsGFpState* pGF))
{
   IPP_BAD_PTR2_RET(method, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );

   /* test method is prime based */
   IPP_BADARG_RET(cpID_Prime!=(method->modulusID & cpID_Prime), ippStsBadArgErr);
   /* test if method is not prime based arbitrary */
   IPP_BADARG_RET(!method->modulus, ippStsBadArgErr);
   /* size of the underlying prime must be equal to primeBitSize parameter*/
   IPP_BADARG_RET(method->modulusBitDeg!=primeBitSize, ippStsBadArgErr);

   {
      /* init GF */
      IppStatus sts = cpGFpInitGFp(primeBitSize, pGF);

      /* set up GF engine */
      if(ippStsNoErr==sts) {
         gsModEngine* pGFE = GFP_PMA(pGF);
         cpGFESet(pGFE, method->modulus, primeBitSize, method->arith);
      }

      return sts;
   }
}

/*F*
// Name: ippsGFpInitArbitrary
//
// Purpose: initializes prime finite field GF(p)
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == pPrime
//                               NULL == pGF
//
//    ippStsSizeErr              !(IPP_MIN_GF_BITSIZE <= primeBitSize <=IPP_MAX_GF_BITSIZE)
//
//    ippStsContextMatchErr      incorrect pPrime context ID
//
//    ippStsBadArgErr            prime <0
//                               bitsize(prime) != primeBitSize
//                               prime <IPP_MIN_GF_CHAR
//                               prime is even
//
//    ippStsNoErr                no error
//
// Parameters:
//    pPrimeBN       pointer to the prime context
//    primeBitSize   length of prime in bits
//    pGF            pointer to Finite Field context is being initialized
*F*/
IPPFUN(IppStatus, ippsGFpInitArbitrary,(const IppsBigNumState* pPrimeBN, int primeBitSize, IppsGFpState* pGF))
{
   IPP_BAD_PTR1_RET(pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );

   IPP_BADARG_RET((primeBitSize< IPP_MIN_GF_BITSIZE) || (primeBitSize> IPP_MAX_GF_BITSIZE), ippStsSizeErr);

   IPP_BAD_PTR1_RET(pPrimeBN);
   pPrimeBN = (IppsBigNumState*)( IPP_ALIGNED_PTR(pPrimeBN, BN_ALIGNMENT) );
   IPP_BADARG_RET(!BN_VALID_ID(pPrimeBN), ippStsContextMatchErr);
   IPP_BADARG_RET(BN_SIGN(pPrimeBN)!= IppsBigNumPOS, ippStsBadArgErr);                                   /* prime is negative */
   IPP_BADARG_RET(BITSIZE_BNU(BN_NUMBER(pPrimeBN),BN_SIZE(pPrimeBN)) != primeBitSize, ippStsBadArgErr);  /* primeBitSize == bitsize(prime) */
   IPP_BADARG_RET((BN_SIZE(pPrimeBN)==1) && (BN_NUMBER(pPrimeBN)[0]<IPP_MIN_GF_CHAR), ippStsBadArgErr);  /* prime < 3 */
   IPP_BADARG_RET(0==(BN_NUMBER(pPrimeBN)[0] & 1), ippStsBadArgErr);                                     /* prime is even */

   {
      /* init GF */
      IppStatus sts = cpGFpInitGFp(primeBitSize, pGF);

      /* set up GF engine */
      if(ippStsNoErr==sts) {
         gsModEngine* pGFE = GFP_PMA(pGF);
         cpGFESet(pGFE, BN_NUMBER(pPrimeBN), primeBitSize, ippsGFpMethod_pArb()->arith);
      }

      return sts;
   }
}

/*F*
// Name: ippsGFpInit
//
// Purpose: initializes prime finite field GF(p)
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == method
//                               NULL == pGF
//
//    ippStsSizeErr              !(IPP_MIN_GF_BITSIZE <= primeBitSize <=IPP_MAX_GF_BITSIZE
//
//    ippStsContextMatchErr      invalid pPrime->idCtx
//
//    ippStsBadArgErr            method != ippsGFpMethod_pXXX() or != ippsGFpMethod_pArb()
//                               prime != method->modulus
//                               prime <0
//                               bitsize(prime) != primeBitSize
//                               prime <IPP_MIN_GF_CHAR
//                               prime is even
//
//    ippStsNoErr                no error
//
// Parameters:
//    pPrimeBN       pointer to the data representation Finite Field element
//    primeBitSize   length of Finite Field data representation array
//    method         pointer to Finite Field Element context
//    pGF            pointer to Finite Field context is being initialized
*F*/
IPPFUN(IppStatus, ippsGFpInit,(const IppsBigNumState* pPrimeBN, int primeBitSize, const IppsGFpMethod* method, IppsGFpState* pGF))
{
   IPP_BADARG_RET(!pPrimeBN && !method, ippStsNullPtrErr);

   IPP_BADARG_RET((primeBitSize< IPP_MIN_GF_BITSIZE) || (primeBitSize> IPP_MAX_GF_BITSIZE), ippStsSizeErr);

   /* use ippsGFpInitFixed() if NULL==pPrimeBN */
   if(!pPrimeBN)
      return ippsGFpInitFixed(primeBitSize, method, pGF);

   /* use ippsGFpInitArbitrary() if NULL==method */
   if(!method)
      return ippsGFpInitArbitrary(pPrimeBN, primeBitSize, pGF);

   /* test parameters if both pPrimeBN and method are defined */
   else {
      IppStatus sts;

      /* test input prime */
      pPrimeBN = (IppsBigNumState*)( IPP_ALIGNED_PTR(pPrimeBN, BN_ALIGNMENT) );
      IPP_BADARG_RET(!BN_VALID_ID(pPrimeBN), ippStsContextMatchErr);
      IPP_BADARG_RET(BN_SIGN(pPrimeBN)!= IppsBigNumPOS, ippStsBadArgErr);                                   /* prime is negative */
      IPP_BADARG_RET(BITSIZE_BNU(BN_NUMBER(pPrimeBN),BN_SIZE(pPrimeBN)) != primeBitSize, ippStsBadArgErr);  /* primeBitSize == bitsize(prime) */
      IPP_BADARG_RET((BN_SIZE(pPrimeBN)==1) && (BN_NUMBER(pPrimeBN)[0]<IPP_MIN_GF_CHAR), ippStsBadArgErr);  /* prime < 3 */
      IPP_BADARG_RET(0==(BN_NUMBER(pPrimeBN)[0] & 1), ippStsBadArgErr);                                     /* prime is even */

      /* test if method is prime based */
      IPP_BADARG_RET(cpID_Prime!=(method->modulusID & cpID_Prime), ippStsBadArgErr);

      /* test if size of the prime is matched to method's prime  */
      IPP_BADARG_RET(method->modulusBitDeg && (primeBitSize!=method->modulusBitDeg), ippStsBadArgErr);

      /* if method assumes fixed prime value */
      if(method->modulus) {
         int primeLen = BITS_BNU_CHUNK(primeBitSize);
         IPP_BADARG_RET(cpCmp_BNU(BN_NUMBER(pPrimeBN), primeLen, method->modulus, primeLen), ippStsBadArgErr);
      }

      /* init GF */
      sts = cpGFpInitGFp(primeBitSize, pGF);

      /* set up GF  and find quadratic nonresidue */
      if(ippStsNoErr==sts) {
         gsModEngine* pGFE = GFP_PMA(pGF);
         cpGFESet(pGFE, BN_NUMBER(pPrimeBN), primeBitSize, method->arith);
      }

      return sts;
   }
}

IPPFUN(IppStatus, ippsGFpScratchBufferSize,(int nExponents, int ExpBitSize, const IppsGFpState* pGF, int* pBufferSize))
{
   IPP_BAD_PTR2_RET(pGF, pBufferSize);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   IPP_BADARG_RET( 0>=nExponents ||nExponents>IPP_MAX_EXPONENT_NUM, ippStsBadArgErr);
   IPP_BADARG_RET( 0>=ExpBitSize, ippStsBadArgErr);

   {
      int elmDataSize = GFP_FELEN(GFP_PMA(pGF))*sizeof(BNU_CHUNK_T);

      /* get window_size */
      int w = (nExponents==1)? cpGFpGetOptimalWinSize(ExpBitSize) : /* use optimal window size, if single-scalar operation */
                               nExponents;                          /* or pseudo-oprimal if multi-scalar operation */

      /* number of table entries */
      int nPrecomputed = 1<<w;

      *pBufferSize = elmDataSize*nPrecomputed + (CACHE_LINE_SIZE-1);

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpElementGetSize,(const IppsGFpState* pGF, int* pElementSize))
{
   IPP_BAD_PTR2_RET(pElementSize, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   *pElementSize = sizeof(IppsGFpElement)
                  +GFP_FELEN(GFP_PMA(pGF))*sizeof(BNU_CHUNK_T);
   return ippStsNoErr;
}


IPPFUN(IppStatus, ippsGFpElementInit,(const Ipp32u* pA, int nsA, IppsGFpElement* pR, IppsGFpState* pGF))
{
   IPP_BAD_PTR2_RET(pR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   IPP_BADARG_RET(0>nsA, ippStsSizeErr);

   {
      int elemLen = GFP_FELEN(GFP_PMA(pGF));

      Ipp8u* ptr = (Ipp8u*)pR;
      ptr += sizeof(IppsGFpElement);
      cpGFpElementConstruct(pR, (BNU_CHUNK_T*)ptr, elemLen);
      return ippsGFpSetElement(pA, nsA, pR, pGF);
   }
}

/*F*
// Name: ippsGFpSetElement
//
// Purpose: Set GF Element
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == pGF
//                               NULL == pElm
//                               NULL == pDataA && nsA>0
//
//    ippStsContextMatchErr      invalid pGF->idCtx
//                               invalid pElm->idCtx
//
//    ippStsSizeErr              pDataA && !(0<=nsA && nsA<GFP_FELEN32())
//
//    ippStsOutOfRangeErr        GFPE_ROOM() != GFP_FELEN()
//                               BNU representation of pDataA[i]..pDataA[i+GFP_FELEN32()-1] >= modulus
//
//    ippStsNoErr                no error
//
// Parameters:
//    pDataA      pointer to the data representation Finite Field element
//    nsA         length of Finite Field data representation array
//    pElm        pointer to Finite Field Element context
//    pGF         pointer to Finite Field context
*F*/
IPPFUN(IppStatus, ippsGFpSetElement,(const Ipp32u* pDataA, int nsA, IppsGFpElement* pElm, IppsGFpState* pGF))
{
   IPP_BAD_PTR2_RET(pElm, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElm), ippStsContextMatchErr );

   IPP_BADARG_RET( !pDataA && (0<nsA), ippStsNullPtrErr);
   IPP_BADARG_RET( pDataA && !(0<=nsA && nsA<=GFP_FELEN32(GFP_PMA(pGF))), ippStsSizeErr );
   IPP_BADARG_RET( GFPE_ROOM(pElm)!=GFP_FELEN(GFP_PMA(pGF)), ippStsOutOfRangeErr );

   {
      IppStatus sts = ippStsNoErr;

      gsModEngine* pGFE = GFP_PMA(pGF);
      int elemLen = GFP_FELEN(pGFE);
      BNU_CHUNK_T* pTmp = cpGFpGetPool(1, pGFE);
      //gres: temporary excluded: assert(NULL!=pTmp);

      ZEXPAND_BNU(pTmp, 0, elemLen);
      if(pDataA && nsA)
         cpGFpxCopyToChunk(pTmp, pDataA, nsA, pGFE);

      if(!cpGFpxSet(GFPE_DATA(pElm), pTmp, elemLen, pGFE))
         sts = ippStsOutOfRangeErr;

      cpGFpReleasePool(1, pGFE);
      return sts;
   }
}

IPPFUN(IppStatus, ippsGFpSetElementRegular,(const IppsBigNumState* pBN, IppsGFpElement* pElm, IppsGFpState* pGF))
{
   IPP_BAD_PTR1_RET(pBN);
   pBN = (IppsBigNumState*)( IPP_ALIGNED_PTR(pBN, BN_ALIGNMENT) );
   IPP_BADARG_RET( !BN_VALID_ID(pBN), ippStsContextMatchErr );
   IPP_BADARG_RET( !BN_POSITIVE(pBN), ippStsOutOfRangeErr);

   return ippsGFpSetElement((Ipp32u*)BN_NUMBER(pBN), BITS2WORD32_SIZE( BITSIZE_BNU(BN_NUMBER((pBN)),BN_SIZE((pBN)))), pElm, pGF);
}

/*F*
// Name: ippsGFpSetElementOctString
//
// Purpose: Set GF Element
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == pGF
//                               NULL == pElm
//                               NULL == pStr && strSize>0
//
//    ippStsContextMatchErr      invalid pGF->idCtx
//                               invalid pElm->idCtx
//
//    ippStsSizeErr              pDataA && !(0<=nsA && nsA<GFP_FELEN32())
//
//    ippStsOutOfRangeErr        GFPE_ROOM() != GFP_FELEN()
//                               BNU representation of pStr[] >= modulus
//
//    ippStsNoErr                no error
//
// Parameters:
//    pDataA      pointer to the data representation Finite Field element
//    nsA         length of Finite Field data representation array
//    pElm        pointer to Finite Field Element context
//    pGF         pointer to Finite Field context
*F*/
IPPFUN(IppStatus, ippsGFpSetElementOctString,(const Ipp8u* pStr, int strSize, IppsGFpElement* pElm, IppsGFpState* pGF))
{
   IPP_BAD_PTR2_RET(pElm, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElm), ippStsContextMatchErr );

   IPP_BADARG_RET( (!pStr && 0<strSize), ippStsNullPtrErr);
   IPP_BADARG_RET(!(0<strSize && strSize<=(int)(GFP_FELEN32(GFP_PMA(pGF))*sizeof(Ipp32u))), ippStsSizeErr );

   IPP_BADARG_RET( GFPE_ROOM(pElm)!=GFP_FELEN(GFP_PMA(pGF)), ippStsOutOfRangeErr);

   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      gsModEngine* pBasicGFE = cpGFpBasic(pGFE);
      int basicDeg = cpGFpBasicDegreeExtension(pGFE);
      int basicElemLen = GFP_FELEN(pBasicGFE);
      int basicSize = BITS2WORD8_SIZE(BITSIZE_BNU(GFP_MODULUS(pBasicGFE),GFP_FELEN(pBasicGFE)));

      BNU_CHUNK_T* pDataElm = GFPE_DATA(pElm);

      int deg, error;
      /* set element to zero */
      cpGFpElementPadd(pDataElm, GFP_FELEN(pGFE), 0);

      /* convert oct string to element (from low to high) */
      for(deg=0, error=0; deg<basicDeg && !error; deg++) {
         int size = IPP_MIN(strSize, basicSize);
         error = NULL == cpGFpSetOctString(pDataElm, pStr, size, pBasicGFE);

         pDataElm += basicElemLen;
         strSize -= size;
         pStr += size;
      }

      return error? ippStsOutOfRangeErr : ippStsNoErr;
   }
}


/*F*
// Name: ippsGFpSetElementRandom
//
// Purpose: Set GF Element Random
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == pGF
//                               NULL == pElm
//                               NULL == rndFunc
//
//    ippStsContextMatchErr      invalid pGF->idCtx
//                               invalid pElm->idCtx
//
//    ippStsOutOfRangeErr        GFPE_ROOM() != GFP_FELEN()
//
//    ippStsErr                  internal error caused by call of rndFunc()
//
//    ippStsNoErr                no error
//
// Parameters:
//    pDataA      pointer to the data representation Finite Field element
//    nsA         length of Finite Field data representation array
//    pElm        pointer to Finite Field Element context
//    pGF         pointer to Finite Field context
*F*/
IPPFUN(IppStatus, ippsGFpSetElementRandom,(IppsGFpElement* pElm, IppsGFpState* pGF,
                                           IppBitSupplier rndFunc, void* pRndParam))
{
   IPP_BAD_PTR3_RET(pElm, pGF, rndFunc);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElm), ippStsContextMatchErr );

   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( GFPE_ROOM(pElm)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);
      return cpGFpxRand(GFPE_DATA(pElm), pGFE, rndFunc, pRndParam)? ippStsNoErr : ippStsErr;
   }
}

IPPFUN(IppStatus, ippsGFpCpyElement, (const IppsGFpElement* pElmA, IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElmA, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGFE)), ippStsOutOfRangeErr);
      cpGFpElementCopy(GFPE_DATA(pElmR), GFPE_DATA(pElmA), GFP_FELEN(pGFE));
      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpGetElement, (const IppsGFpElement* pElm, Ipp32u* pDataA, int nsA, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElm, pDataA, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElm), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( GFPE_ROOM(pElm)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);
      IPP_BADARG_RET( !(0<nsA && nsA>=GFP_FELEN32(pGFE)), ippStsSizeErr );

      {
         int elemLen = GFP_FELEN(pGFE);
         BNU_CHUNK_T* pTmp = cpGFpGetPool(1, pGFE);
         //gres: temporary excluded: assert(NULL!=pTmp);

         cpGFpxGet(pTmp, elemLen, GFPE_DATA(pElm), pGFE);
         cpGFpxCopyFromChunk(pDataA, pTmp, pGFE);

         cpGFpReleasePool(1, pGFE);
         return ippStsNoErr;
      }
   }
}

IPPFUN(IppStatus, ippsGFpGetElementOctString,(const IppsGFpElement* pElm, Ipp8u* pStr, int strSize, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pStr, pElm, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElm), ippStsContextMatchErr );
   IPP_BADARG_RET( 0>=strSize, ippStsSizeErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( GFPE_ROOM(pElm)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);
      {
         gsModEngine* pBasicGFE = cpGFpBasic(pGFE);
         int basicDeg = cpGFpBasicDegreeExtension(pGFE);
         int basicElemLen = GFP_FELEN(pBasicGFE);
         int basicSize = BITS2WORD8_SIZE(BITSIZE_BNU(GFP_MODULUS(pBasicGFE),GFP_FELEN(pBasicGFE)));

         BNU_CHUNK_T* pDataElm = GFPE_DATA(pElm);
         int deg;
         for(deg=0; deg<basicDeg; deg++) {
            int size = IPP_MIN(strSize, basicSize);
            cpGFpGetOctString(pStr, size, pDataElm, pBasicGFE);

            pDataElm += basicElemLen;
            pStr += size;
            strSize -= size;
         }

         return ippStsNoErr;
      }
   }
}

IPPFUN(IppStatus, ippsGFpCmpElement,(const IppsGFpElement* pElmA, const IppsGFpElement* pElmB,
                                     int* pResult,
                                     const IppsGFpState* pGF))
{
   IPP_BAD_PTR4_RET(pElmA, pElmB, pResult, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmB), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmB)!=GFP_FELEN(pGFE)), ippStsOutOfRangeErr);
      {
         int flag = cpGFpElementCmp(GFPE_DATA(pElmA), GFPE_DATA(pElmB), GFP_FELEN(pGFE));
         if( GFP_IS_BASIC(pGFE) )
            *pResult = (0==flag)? IPP_IS_EQ : (0<flag)? IPP_IS_GT : IPP_IS_LT;
         else
            *pResult = (0==flag)? IPP_IS_EQ : IPP_IS_NE;
         return ippStsNoErr;
      }
   }
}

IPPFUN(IppStatus, ippsGFpIsZeroElement,(const IppsGFpElement* pElmA,
                                     int* pResult,
                                     const IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElmA, pResult, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);
      {
         int flag = GFP_IS_ZERO(GFPE_DATA(pElmA), GFP_FELEN(pGFE));
         *pResult = (1==flag)? IPP_IS_EQ : IPP_IS_NE;
         return ippStsNoErr;
      }
   }
}

IPPFUN(IppStatus, ippsGFpIsUnityElement,(const IppsGFpElement* pElmA,
                                     int* pResult,
                                     const IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElmA, pResult, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);
      {
         gsModEngine* pBasicGFE = cpGFpBasic(pGFE);
         int basicElmLen = GFP_FELEN(pBasicGFE);
         BNU_CHUNK_T* pUnity = GFP_MNT_R(pBasicGFE);

         int elmLen = GFP_FELEN(pGFE);
         int flag;

         FIX_BNU(pUnity, basicElmLen);
         FIX_BNU(GFPE_DATA(pElmA), elmLen);

         flag = (basicElmLen==elmLen) && (0 == cpGFpElementCmp(GFPE_DATA(pElmA), pUnity, elmLen));
         *pResult = (1==flag)? IPP_IS_EQ : IPP_IS_NE;
         return ippStsNoErr;
      }
   }
}

IPPFUN(IppStatus, ippsGFpConj,(const IppsGFpElement* pElmA,
                                     IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElmA, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGFE)), ippStsOutOfRangeErr);
      IPP_BADARG_RET( 2!=GFP_EXTDEGREE(pGFE), ippStsBadArgErr )

      cpGFpxConj(GFPE_DATA(pElmR), GFPE_DATA(pElmA), pGFE);
      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpNeg,(const IppsGFpElement* pElmA,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElmA, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGFE)), ippStsOutOfRangeErr);

      GFP_METHOD(pGFE)->neg(GFPE_DATA(pElmR), GFPE_DATA(pElmA), pGFE);
      return ippStsNoErr;
   }
}


IPPFUN(IppStatus, ippsGFpInv,(const IppsGFpElement* pElmA,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElmA, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGFE)), ippStsOutOfRangeErr);
      IPP_BADARG_RET( GFP_IS_ZERO(GFPE_DATA(pElmA),GFP_FELEN(pGFE)), ippStsDivByZeroErr );

      return NULL != cpGFpxInv(GFPE_DATA(pElmR), GFPE_DATA(pElmA), pGFE)? ippStsNoErr : ippStsBadArgErr;
   }
}


IPPFUN(IppStatus, ippsGFpSqrt,(const IppsGFpElement* pElmA,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElmA, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( !GFP_IS_BASIC(pGFE), ippStsBadArgErr )
      IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGFE)), ippStsOutOfRangeErr);

      return cpGFpSqrt(GFPE_DATA(pElmR), GFPE_DATA(pElmA), pGFE)? ippStsNoErr : ippStsQuadraticNonResidueErr;
   }
}


IPPFUN(IppStatus, ippsGFpAdd,(const IppsGFpElement* pElmA, const IppsGFpElement* pElmB,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR4_RET(pElmA, pElmB, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmB), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmB)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGFE)), ippStsOutOfRangeErr);

      GFP_METHOD(pGFE)->add(GFPE_DATA(pElmR), GFPE_DATA(pElmA), GFPE_DATA(pElmB), pGFE);
      return ippStsNoErr;
   }
}


IPPFUN(IppStatus, ippsGFpSub,(const IppsGFpElement* pElmA, const IppsGFpElement* pElmB,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR4_RET(pElmA, pElmB, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmB), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmB)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGFE)), ippStsOutOfRangeErr);

      GFP_METHOD(pGFE)->sub(GFPE_DATA(pElmR), GFPE_DATA(pElmA), GFPE_DATA(pElmB), pGFE);
      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpMul,(const IppsGFpElement* pElmA, const IppsGFpElement* pElmB,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR4_RET(pElmA, pElmB, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmB), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmB)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGFE)), ippStsOutOfRangeErr);

      GFP_METHOD(pGFE)->mul(GFPE_DATA(pElmR), GFPE_DATA(pElmA), GFPE_DATA(pElmB),pGFE);
      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpSqr,(const IppsGFpElement* pElmA,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElmA, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGFE)), ippStsOutOfRangeErr);

      GFP_METHOD(pGFE)->sqr(GFPE_DATA(pElmR), GFPE_DATA(pElmA), pGFE);
      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpAdd_PE,(const IppsGFpElement* pElmA, const IppsGFpElement* pParentElmB,
                                 IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR4_RET(pElmA, pParentElmB, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pParentElmB), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( GFP_IS_BASIC(pGFE), ippStsBadArgErr )
      IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGFE)), ippStsOutOfRangeErr);
      IPP_BADARG_RET( (GFPE_ROOM(pParentElmB)!=GFP_FELEN(GFP_PARENT(pGFE))), ippStsOutOfRangeErr);

      cpGFpxAdd_GFE(GFPE_DATA(pElmR), GFPE_DATA(pElmA), GFPE_DATA(pParentElmB), pGFE);
      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpSub_PE,(const IppsGFpElement* pElmA, const IppsGFpElement* pParentElmB,
                                 IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR4_RET(pElmA, pParentElmB, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pParentElmB), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( GFP_IS_BASIC(pGFE), ippStsBadArgErr )
      IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGFE)), ippStsOutOfRangeErr);
      IPP_BADARG_RET( (GFPE_ROOM(pParentElmB)!=GFP_FELEN(GFP_PARENT(pGFE))), ippStsOutOfRangeErr);

      cpGFpxSub_GFE(GFPE_DATA(pElmR), GFPE_DATA(pElmA), GFPE_DATA(pParentElmB), pGFE);
      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpMul_PE,(const IppsGFpElement* pElmA, const IppsGFpElement* pParentElmB,
                                 IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR4_RET(pElmA, pParentElmB, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pParentElmB), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( GFP_IS_BASIC(pGFE), ippStsBadArgErr )
      IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGFE)), ippStsOutOfRangeErr);
      IPP_BADARG_RET( (GFPE_ROOM(pParentElmB)!=GFP_FELEN(GFP_PARENT(pGFE))), ippStsOutOfRangeErr);

      cpGFpxMul_GFE(GFPE_DATA(pElmR), GFPE_DATA(pElmA), GFPE_DATA(pParentElmB), pGFE);
      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpExp,(const IppsGFpElement* pElmA, const IppsBigNumState* pE,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF,
                                    Ipp8u* pScratchBuffer))
{
   IPP_BAD_PTR4_RET(pElmA, pE, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );

   pE = (IppsBigNumState*)( IPP_ALIGNED_PTR(pE, BN_ALIGNMENT) );
   IPP_BADARG_RET( !BN_VALID_ID(pE), ippStsContextMatchErr );
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGFE)), ippStsOutOfRangeErr);

      cpGFpxExp(GFPE_DATA(pElmR), GFPE_DATA(pElmA), BN_NUMBER(pE), BN_SIZE(pE), pGFE, pScratchBuffer);
      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpMultiExp,(const IppsGFpElement* const ppElmA[], const IppsBigNumState* const ppE[], int nItems,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF,
                                    Ipp8u* pScratchBuffer))
{
   IPP_BAD_PTR2_RET(ppElmA, ppE);

   if(nItems==1)
      return ippsGFpExp(ppElmA[0], ppE[0], pElmR, pGF, pScratchBuffer);

   else {
      /* test number of exponents */
      IPP_BADARG_RET(1>nItems || nItems>IPP_MAX_EXPONENT_NUM, ippStsBadArgErr);

      IPP_BAD_PTR2_RET(pElmR, pGF);

      pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
      IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
      IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );
      {
         int n;

         gsModEngine* pGFE = GFP_PMA(pGF);
         IPP_BADARG_RET( GFPE_ROOM(pElmR)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);

         /* test all ppElmA[] and ppE[] pairs */
         for(n=0; n<nItems; n++) {
            const IppsGFpElement* pElmA = ppElmA[n];
            const IppsBigNumState* pE = ppE[n];
            IPP_BAD_PTR2_RET(pElmA, pE);

            IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
            pE = (IppsBigNumState*)( IPP_ALIGNED_PTR(pE, BN_ALIGNMENT) );
            IPP_BADARG_RET( !BN_VALID_ID(pE), ippStsContextMatchErr );

            IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGFE)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGFE)), ippStsOutOfRangeErr);
         }

         if(NULL==pScratchBuffer) {
            mod_mul mulF = GFP_METHOD(pGFE)->mul;

            BNU_CHUNK_T* pTmpR = cpGFpGetPool(1, pGFE);
            //gres: temporary excluded: assert(NULL!=pTmpR);

            cpGFpxExp(GFPE_DATA(pElmR), GFPE_DATA(ppElmA[0]), BN_NUMBER(ppE[0]), BN_SIZE(ppE[0]), pGFE, 0);
            for(n=1; n<nItems; n++) {
               cpGFpxExp(pTmpR, GFPE_DATA(ppElmA[n]), BN_NUMBER(ppE[n]), BN_SIZE(ppE[n]), pGFE, 0);
               mulF(GFPE_DATA(pElmR), GFPE_DATA(pElmR), pTmpR, pGFE);
            }
   
            cpGFpReleasePool(1, pGFE);
         }

         else {
            const BNU_CHUNK_T* ppAdata[IPP_MAX_EXPONENT_NUM];
            const BNU_CHUNK_T* ppEdata[IPP_MAX_EXPONENT_NUM];
            int nsEdataLen[IPP_MAX_EXPONENT_NUM];
            for(n=0; n<nItems; n++) {
               ppAdata[n] = GFPE_DATA(ppElmA[n]);
               ppEdata[n] = BN_NUMBER(ppE[n]);
               nsEdataLen[n] = BN_SIZE(ppE[n]);
            }
            cpGFpxMultiExp(GFPE_DATA(pElmR), ppAdata, ppEdata, nsEdataLen, nItems, pGFE, pScratchBuffer);
         }

         return ippStsNoErr;
      }
   }
}

/*F*
// Name: ippsGFpSetElementHash
//
// Purpose: Set GF Element Hash of the Message
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == pGF
//                               NULL == pElm
//                               NULL == pMsg if msgLen>0
//
//    ippStsNotSupportedModeErr  hashID is not supported
//
//    ippStsContextMatchErr      invalid pGF->idCtx
//                               invalid pElm->idCtx
//
//    ippStsOutOfRangeErr        GFPE_ROOM() != GFP_FELEN()
//
//    ippStsNoErr                no error
//
// Parameters:
//    pMsg     pointer to the message is beinh hashed
//    msgLen   length of the message above
//    pElm     pointer to Finite Field Element context
//    pGF      pointer to Finite Field context
//    hashID   applied hash algothith ID
*F*/
IPPFUN(IppStatus, ippsGFpSetElementHash,(const Ipp8u* pMsg, int msgLen, IppsGFpElement* pElm, IppsGFpState* pGF, IppHashAlgId hashID))
{
   /* get algorithm id */
   hashID = cpValidHashAlg(hashID);
   IPP_BADARG_RET(ippHashAlg_Unknown==hashID, ippStsNotSupportedModeErr);

   /* test message length and pointer */
   IPP_BADARG_RET((msgLen<0), ippStsLengthErr);
   IPP_BADARG_RET((msgLen && !pMsg), ippStsNullPtrErr);

   IPP_BAD_PTR2_RET(pElm, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr);
   IPP_BADARG_RET( !GFPE_TEST_ID(pElm), ippStsContextMatchErr);
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( !GFP_IS_BASIC(pGFE), ippStsBadArgErr);
      IPP_BADARG_RET( GFPE_ROOM(pElm)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);

      {
         Ipp8u md[MAX_HASH_SIZE];
         BNU_CHUNK_T hashVal[(MAX_HASH_SIZE*8)/BITSIZE(BNU_CHUNK_T)+1]; /* +1 to meet cpMod_BNU() implementtaion specific */
         IppStatus sts = ippsHashMessage(pMsg, msgLen, md, hashID);

         if(ippStsNoErr==sts) {
            int elemLen = GFP_FELEN(pGFE);
            int hashLen = cpHashAlgAttr[hashID].hashSize;
            int hashValLen = cpFromOctStr_BNU(hashVal, md, hashLen);
            hashValLen = cpMod_BNU(hashVal, hashValLen, GFP_MODULUS(pGFE), elemLen);
            cpGFpSet(GFPE_DATA(pElm), hashVal, hashValLen, pGFE);
         }

         return sts;
      }
   }
}

IPPFUN(IppStatus, ippsGFpSetElementHash_rmf,(const Ipp8u* pMsg, int msgLen, IppsGFpElement* pElm, IppsGFpState* pGF, const IppsHashMethod* pMethod))
{
   /* test method pointer */
   IPP_BAD_PTR1_RET(pMethod);

   /* test message length and pointer */
   IPP_BADARG_RET((msgLen<0), ippStsLengthErr);
   IPP_BADARG_RET((msgLen && !pMsg), ippStsNullPtrErr);

   IPP_BAD_PTR2_RET(pElm, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr);
   IPP_BADARG_RET( !GFPE_TEST_ID(pElm), ippStsContextMatchErr);
   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      IPP_BADARG_RET( !GFP_IS_BASIC(pGFE), ippStsBadArgErr);
      IPP_BADARG_RET( GFPE_ROOM(pElm)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);

      {
         Ipp8u md[MAX_HASH_SIZE];
         BNU_CHUNK_T hashVal[(MAX_HASH_SIZE*8)/BITSIZE(BNU_CHUNK_T)+1]; /* +1 to meet cpMod_BNU() implementtaion specific */
         IppStatus sts = ippsHashMessage_rmf(pMsg, msgLen, md, pMethod);

         if(ippStsNoErr==sts) {
            int elemLen = GFP_FELEN(pGFE);
            int hashLen = pMethod->hashLen;
            int hashValLen = cpFromOctStr_BNU(hashVal, md, hashLen);
            hashValLen = cpMod_BNU(hashVal, hashValLen, GFP_MODULUS(pGFE), elemLen);
            cpGFpSet(GFPE_DATA(pElm), hashVal, hashValLen, pGFE);
         }

         return sts;
      }
   }
}
