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
//  Purpose:
//     Intel(R) Integrated Performance Primitives
//     Cryptographic Primitives
//     Internal GF(p) basic Definitions & Function Prototypes
//
*/

#if !defined(_PCP_GFP_H_)
#define _PCP_GFP_H_

#include "pcpbn.h"
#include "pcpgfpmethod.h"
#include "pcpmontgomery.h"

/* GF element */
typedef struct _cpGFpElement {
   IppCtxId    idCtx;   /* GF() element ident */
   int         length;  /* length of element (in BNU_CHUNK_T) */
   BNU_CHUNK_T*  pData;
} cpGFpElement;

#define GFPE_ID(pCtx)      ((pCtx)->idCtx)
#define GFPE_ROOM(pCtx)    ((pCtx)->length)
#define GFPE_DATA(pCtx)    ((pCtx)->pData)

#define GFPE_TEST_ID(pCtx) (GFPE_ID((pCtx))==idCtxGFPE)


/* GF(p) context */
typedef struct _cpGFp cpGF_T;

typedef struct _cpGFp {
   IppCtxId       idCtx;         /* GFp spec ident    */
   int            elemBitLen;    /* size of field element (in bits) */
   int            elemLen;       /* size of field element (in BNU_CHUNK_T) */
   int            elemLen32;     /* sizeof of field element (in Ipp32u) */
   int            pelemLen;      /* sizeof pool element (in BNU_CHUNK_T) */
   int            gfdegree;      /* degree of extension (==1 means basic GF(p)) */
   int            modulusTypeSpc;/* modulus type specific */
   int            epidParams;    /* EPID 2.0 specific parameters */
   cpGF_T*        pGroundGF;     /* ground GF (refference on itself if basic GF(p)) */
                                 /* = methods: = */
   gfadd          add;           /*    - gf add  */
   gfsub          sub;           /*    - gf sub  */
   gfneg          neg;           /*    - gf neg  */
   gfdiv2         div2;          /*    - gf div by 2 */
   gfmul2         mul2;          /*    - gf mul by 2 */
   gfmul3         mul3;          /*    - gf mul by 3 */
   gfmul          mul;           /*    - gf mul  */
   gfsqr          sqr;           /*    - gf sqr  */
   gfencode       encode;        /*    - to internal representation */
   gfencode       decode;        /*    - from internal representation */
                                 /* ============ */
   BNU_CHUNK_T*   pModulus;      /* modulus or irreducible polypomial (without hight order term ==1) */
   BNU_CHUNK_T*   pHalfModulus;  /* modulus/2 if basic, NULL if extension */
   BNU_CHUNK_T*   pQnr;          /* quadratic non-residue if basic, NULL if extension */
   IppsMontState* pMontState;    /* montgomery engine if basic, NULL if extension */
   BNU_CHUNK_T*   pElemPool;     /* pool of temporary field elements */
} cpGFp;

#define GFP_ALIGNMENT   ((int)(sizeof(void*)))

/* Local definitions */
#define GF_MAX_BITSIZE      (IPP_MAX_GF_BITSIZE)      /* max bitsize for GF element */
#define GF_POOL_SIZE        (IPP_MAX_EXPONENT_NUM+3)  /* num of elements into the pool */
#define GF_RAND_ADD_BITS    (128)                     /* parameter of random element generation ?? == febits/2 */

#define GFP_ID(pCtx)          ((pCtx)->idCtx)
#define GFP_FEBITLEN(pCtx)    ((pCtx)->elemBitLen)
#define GFP_FELEN(pCtx)       ((pCtx)->elemLen)
#define GFP_FELEN32(pCtx)     ((pCtx)->elemLen32) /////????!!!!
#define GFP_PELEN(pCtx)       ((pCtx)->pelemLen)
#define GFP_DEGREE(pCtx)      ((pCtx)->gfdegree)
#define FIELD_POLY_TYPE(pCtx) ((pCtx)->modulusTypeSpc)
#define GFP_GROUNDGF(pCtx)    ((pCtx)->pGroundGF)
#define GFP_MODULUS(pCtx)     ((pCtx)->pModulus)
#define GFP_HMODULUS(pCtx)    ((pCtx)->pHalfModulus) /* for Sqrt() function only */
#define GFP_QNR(pCtx)         ((pCtx)->pQnr)
#define GFP_POOL(pCtx)        ((pCtx)->pElemPool)
#define GFP_MONT(pCtx)        ((pCtx)->pMontState)

/* type of field polynomial: */
#define ARBITRARY (0)   /* arbitrary */
#define BINOMIAL  (1)   /* binomial */

//#define GFP_FEBITSIZE(pCtx)   (BITSIZE_BNU(GFP_MODULUS((pCtx)),GFP_FELEN((pCtx))))
#define GFP_IS_BASIC(pCtx)    (GFP_GROUNDGF((pCtx))==(pCtx))
#define GFP_TEST_ID(pCtx)     (GFP_ID((pCtx))==idCtxGFP)

/*
// get/release n element from/to the pool
*/
__INLINE BNU_CHUNK_T* cpGFpGetPool(int n, IppsGFpState* pGF)
{
   BNU_CHUNK_T* pPool = GFP_POOL(pGF);
   GFP_POOL(pGF) += n*GFP_PELEN(pGF);
   return pPool;
}
__INLINE void cpGFpReleasePool(int n, IppsGFpState* pGF)
{
   GFP_POOL(pGF) -= n*GFP_PELEN(pGF);
}



__INLINE int cpGFpElementLen(const BNU_CHUNK_T* pE, int nsE)
{
   for(; nsE>1 && 0==pE[nsE-1]; nsE--) ;
   return nsE;
}
__INLINE BNU_CHUNK_T* cpGFpElementCopy(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pE, int nsE)
{
   int n;
   for(n=0; n<nsE; n++) pR[n] = pE[n];
   return pR;
}
__INLINE BNU_CHUNK_T* cpGFpElementPadd(BNU_CHUNK_T* pE, int nsE, BNU_CHUNK_T filler)
{
   int n;
   for(n=0; n<nsE; n++) pE[n] = filler;
   return pE;
}
__INLINE BNU_CHUNK_T* cpGFpElementCopyPadd(BNU_CHUNK_T* pR, int nsR, const BNU_CHUNK_T* pE, int nsE)
{
   int n;
   for(n=0; n<nsE; n++) pR[n] = pE[n];
   for(; n<nsR; n++) pR[n] = 0;
   return pR;
}
__INLINE int cpGFpElementCmp(const BNU_CHUNK_T* pE, const BNU_CHUNK_T* pX, int nsE)
{
   for(; nsE>1 && pE[nsE-1]==pX[nsE-1]; nsE--)
      ;
   return pE[nsE-1]==pX[nsE-1]? 0 : pE[nsE-1]>pX[nsE-1]? 1:-1;
}
__INLINE int cpGFpElementIsEquChunk(const BNU_CHUNK_T* pE, int nsE, BNU_CHUNK_T x)
{
   int isEqu = (pE[0] == x);
   return isEqu && (1==cpGFpElementLen(pE, nsE));
}
__INLINE BNU_CHUNK_T* cpGFpElementSetChunk(BNU_CHUNK_T* pR, int nsR, BNU_CHUNK_T x)
{
   return cpGFpElementCopyPadd(pR, nsR, &x, 1);
}


#define GFP_LT(a,b,size)  (-1==cpGFpElementCmp((a),(b),(size)))
#define GFP_EQ(a,b,size)  ( 0==cpGFpElementCmp((a),(b),(size)))
#define GFP_GT(a,b,size)  ( 1==cpGFpElementCmp((a),(b),(size)))

#define GFP_IS_ZERO(a,size)  cpGFpElementIsEquChunk((a),(size), 0)
#define GFP_IS_ONE(a,size)   cpGFpElementIsEquChunk((a),(size), 1)

#define GFP_ZERO(a,size)      cpGFpElementSetChunk((a),(size), 0)
#define GFP_ONE(a,size)       cpGFpElementSetChunk((a),(size), 1)

#define GFP_IS_EVEN(a)  (0==((a)[0]&1))
#define GFP_IS_ODD(a)   (1==((a)[0]&1))

__INLINE IppsBigNumState* cpGFpInitBigNum(IppsBigNumState* pBN, int len, BNU_CHUNK_T* pNumBuffer, BNU_CHUNK_T* pTmpBuffer)
{
   BN_ID(pBN)     = idCtxBigNum;
   BN_SIGN(pBN)   = ippBigNumPOS;
   BN_NUMBER(pBN) = pNumBuffer;
   BN_BUFFER(pBN) = pTmpBuffer;
   BN_ROOM(pBN)   = len;
   BN_SIZE(pBN)   = 0;
   return pBN;
}

__INLINE IppsBigNumState* cpGFpSetBigNum(IppsBigNumState* pBN, int len, const BNU_CHUNK_T* pBNU, BNU_CHUNK_T* pTmpBuffer)
{
   cpGFpInitBigNum(pBN, len, (BNU_CHUNK_T*)pBNU, pTmpBuffer);
   FIX_BNU(pBNU, len);
   BN_SIZE(pBN) = len;
   return pBN;
}

/* construct GF element */
__INLINE IppsGFpElement* cpGFpElementConstruct(IppsGFpElement* pR, BNU_CHUNK_T* pDataBufer, int ns)
{
   GFPE_ID(pR) = idCtxGFPE;
   GFPE_ROOM(pR) = ns;
   GFPE_DATA(pR) = pDataBufer;
   return pR;
}


/* size of GFp context, init and setup */
int cpGFpGetSize(int bitSize);
IppStatus cpGFpInitGFp(int primeBitSize, IppsGFpState* pGF);
IppStatus cpGFpSetGFp(const IppsBigNumState* pPrime, const IppsGFpMethod* method, IppsGFpState* pGF);

/* operations */
BNU_CHUNK_T* cpGFpRand(BNU_CHUNK_T* pR, IppsGFpState* pGF, IppBitSupplier rndFunc, void* pRndParam);
#define cpGFpSet OWNAPI(cpGFpSet)
BNU_CHUNK_T* cpGFpSet (BNU_CHUNK_T* pR, const BNU_CHUNK_T* pDataA, int nsA, IppsGFpState* pGF);
#define cpGFpGet OWNAPI(cpGFpGet)
BNU_CHUNK_T* cpGFpGet (BNU_CHUNK_T* pDataA, int nsA, const BNU_CHUNK_T* pR, IppsGFpState* pGF);
#define cpGFpSetOctString OWNAPI(cpGFpSetOctString)
BNU_CHUNK_T* cpGFpSetOctString(BNU_CHUNK_T* pR, const Ipp8u* pStr, int strSize, IppsGFpState* pGF);
#define cpGFpGetOctString OWNAPI(cpGFpGetOctString)
Ipp8u*       cpGFpGetOctString(Ipp8u* pStr, int strSize, const BNU_CHUNK_T* pA, IppsGFpState* pGF);

#define cpGFpNeg OWNAPI(cpGFpNeg)
BNU_CHUNK_T* cpGFpNeg  (BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF);
#define cpGFpInv OWNAPI(cpGFpInv)
BNU_CHUNK_T* cpGFpInv  (BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF);
#define cpGFpHalve OWNAPI(cpGFpHalve)
BNU_CHUNK_T* cpGFpHalve(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF);
#define cpGFpAdd OWNAPI(cpGFpAdd)
BNU_CHUNK_T* cpGFpAdd  (BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGF);
#define cpGFpSub OWNAPI(cpGFpSub)
BNU_CHUNK_T* cpGFpSub  (BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGF);
#define cpGFpMul OWNAPI(cpGFpMul)
BNU_CHUNK_T* cpGFpMul  (BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGF);
#define cpGFpSqr OWNAPI(cpGFpSqr)
BNU_CHUNK_T* cpGFpSqr  (BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF);
#define cpGFpExp OWNAPI(cpGFpExp)
BNU_CHUNK_T* cpGFpExp  (BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pE, int nsE, IppsGFpState* pGF);
          int cpGFpSqrt(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF);

#if(_IPP32E >= _IPP32E_M7)
#define cp256pAdd OWNAPI(cp256pAdd)
BNU_CHUNK_T* cp256pAdd(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGF);
#define cp256pSub OWNAPI(cp256pSub)
BNU_CHUNK_T* cp256pSub(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGF);
#define cp256pNeg OWNAPI(cp256pNeg)
BNU_CHUNK_T* cp256pNeg(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF);
#define cp256pMul OWNAPI(cp256pMul)
BNU_CHUNK_T* cp256pMul(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGF);
#define cp256pSqr OWNAPI(cp256pSqr)
BNU_CHUNK_T* cp256pSqr(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF);
#define cp256pHalve OWNAPI(cp256pHalve)
BNU_CHUNK_T* cp256pHalve(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF);
#endif

#define cpGFpInitBigNum OWNAPI(cpGFpInitBigNum)
IppsBigNumState* cpGFpInitBigNum(IppsBigNumState* pBN, int len, BNU_CHUNK_T* pNumBuffer, BNU_CHUNK_T* pTmpBuffer);
#define cpGFpSetBigNum OWNAPI(cpGFpSetBigNum)
IppsBigNumState* cpGFpSetBigNum(IppsBigNumState* pBN, int len, const BNU_CHUNK_T* pBNU, BNU_CHUNK_T* pTmpBuffer);

#endif /* _PCP_GFP_H_ */
