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
//     Intel(R) Performance Primitives. Cryptography Primitives.
//     Operations over GF(p) ectension.
// 
//     Context:
//        ippsGFpxGetSize
//        ippsGFpxInit
//        ippsGFpGetInfo
// 
*/

#include "owndefs.h"
#include "owncp.h"

#include "pcpgfpstuff.h"
#include "pcpgfpxstuff.h"

/* Get context size */
IPPFUN(IppStatus, ippsGFpxGetSize, (const IppsGFpState* pGroundGF, int deg, int* pSizeInBytes))
{
   IPP_BAD_PTR2_RET(pGroundGF, pSizeInBytes);
   IPP_BADARG_RET( deg<IPP_MIN_GF_EXTDEG || deg >IPP_MAX_GF_EXTDEG, ippStsBadArgErr);
   pGroundGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGroundGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGroundGF), ippStsContextMatchErr );

   {
      int elemGroundLen = GFP_FELEN(pGroundGF);
      int elemLen = elemGroundLen * deg;
      *pSizeInBytes = sizeof(IppsGFpState)
                     +elemLen * sizeof(BNU_CHUNK_T) /* field polynomial coeff. excluding leading 1 */
                     +elemLen * sizeof(BNU_CHUNK_T) * GFPX_POOL_SIZE /* pool of temporary variables */
                     +GFP_ALIGNMENT-1;
      return ippStsNoErr;
   }
}

static void InitGFpxCtx(const IppsGFpState* pGroundGF, int extDeg, const IppsGFpMethod* method, IppsGFpState* pGFpx)
{
 //int elemBitLen = extDeg * GFP_FEBITLEN(pGroundGF);
   int elemLen = extDeg * GFP_FELEN(pGroundGF);
   int elemLen32 = extDeg * GFP_FELEN32(pGroundGF);

   Ipp8u* ptr = (Ipp8u*)pGFpx + sizeof(IppsGFpState);

   /* context identifier */
   GFP_ID(pGFpx) = idCtxGFP;
   /* extension degree */
   GFP_DEGREE(pGFpx) = extDeg;
   /* length of element */
   GFP_FEBITLEN(pGFpx)= 0;//elemBitLen;
   GFP_FELEN(pGFpx)= elemLen;
   GFP_FELEN32(pGFpx) = elemLen32;
   GFP_PELEN(pGFpx)   = elemLen;
   FIELD_POLY_TYPE(pGFpx) = ARBITRARY;

   pGFpx->add = method->add;
   pGFpx->sub = method->sub;
   pGFpx->neg = method->neg;
   pGFpx->div2= method->div2;
   pGFpx->mul2= method->mul2;
   pGFpx->mul3= method->mul3;
   pGFpx->mul = method->mul;
   pGFpx->sqr = method->sqr;
   pGFpx->encode = method->encode;
   pGFpx->decode = method->decode;

   /* save ground GF() context address */
   GFP_GROUNDGF(pGFpx) = (IppsGFpState*)pGroundGF;
   /* coefficients of field polynomial */
   GFP_MODULUS(pGFpx) = (BNU_CHUNK_T*)(ptr);    ptr += elemLen * sizeof(BNU_CHUNK_T);
   /* 1/2 modulus: no matter */
   GFP_HMODULUS(pGFpx) = NULL;
   /* quadratic non-residue: no matter */
   GFP_QNR(pGFpx) = NULL;
   /* montgomery engine: no matter */
   GFP_MONT(pGFpx) = NULL;
   /* pool addresses */
   GFP_POOL(pGFpx) = (BNU_CHUNK_T*)(IPP_ALIGNED_PTR(ptr, (int)sizeof(BNU_CHUNK_T)));

   cpGFpElementPadd(GFP_MODULUS(pGFpx), elemLen, 0);
}


/* Init context by arbitrary irreducible polynomial */
IPPFUN(IppStatus, ippsGFpxInit,(const IppsGFpState* pGroundGF, int extDeg,
                                const IppsGFpElement* const ppGroundElm[], int nElm,
                                const IppsGFpMethod* method, IppsGFpState* pGFpx))
{
   IPP_BAD_PTR4_RET(pGFpx, pGroundGF, ppGroundElm, method);
   pGroundGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGroundGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGroundGF), ippStsContextMatchErr );

   IPP_BADARG_RET( extDeg<IPP_MIN_GF_EXTDEG || extDeg>IPP_MAX_GF_EXTDEG, ippStsBadArgErr);
   IPP_BADARG_RET( 1>nElm || nElm>IPP_MAX_GF_EXTDEG, ippStsSizeErr);
   IPP_BADARG_RET( nElm>extDeg, ippStsBadArgErr);

   pGFpx = (IppsGFpState*)( IPP_ALIGNED_PTR(pGFpx, GFP_ALIGNMENT) );
   InitGFpxCtx(pGroundGF, extDeg, method, pGFpx);

   {
      BNU_CHUNK_T* pPoly = GFP_MODULUS(pGFpx);
      int polyTermlen = GFP_FELEN(pGroundGF);
      int n;
      for(n=0; n<nElm; n++, pPoly+=polyTermlen) {
         const IppsGFpElement* pGroundElm = ppGroundElm[n];

         /* test element */
         IPP_BAD_PTR1_RET(pGroundElm);
         IPP_BADARG_RET(!GFPE_TEST_ID(pGroundElm), ippStsContextMatchErr);
         IPP_BADARG_RET(GFPE_ROOM(pGroundElm)!=polyTermlen, ippStsOutOfRangeErr);

         /* copy element */
         cpGFpElementCopy(pPoly, GFPE_DATA(pGroundElm), polyTermlen);
      }
   }

   return ippStsNoErr;
}

/* Init context by arbitrary irreducible binimial */
IPPFUN(IppStatus, ippsGFpxInitBinomial,(const IppsGFpState* pGroundGF, int extDeg,
                                        const IppsGFpElement* pGroundElm,
                                        const IppsGFpMethod* method,
                                        IppsGFpState* pGFpx))
{
   IPP_BAD_PTR4_RET(pGFpx, pGroundGF, pGroundElm, method);
   pGroundGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGroundGF, GFP_ALIGNMENT) );
   pGFpx = (IppsGFpState*)( IPP_ALIGNED_PTR(pGFpx, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGroundGF), ippStsContextMatchErr );

   IPP_BADARG_RET( extDeg<IPP_MIN_GF_EXTDEG || extDeg>IPP_MAX_GF_EXTDEG, ippStsBadArgErr);

   /* init context */
   InitGFpxCtx(pGroundGF, extDeg, method, pGFpx);

   /* store low-order coefficient of irresucible into the context */
   cpGFpElementCopy(GFP_MODULUS(pGFpx), GFPE_DATA(pGroundElm), GFP_FELEN(pGroundGF));
   FIELD_POLY_TYPE(pGFpx) = BINOMIAL;

   return ippStsNoErr;
}

#if 0
/* get general info */
IPPFUN(IppStatus, ippsGFpGetInfo,(const IppsGFpState* pGFpx, IppsGFpInfo* pInfo))
{
   IPP_BAD_PTR2_RET(pGFpx, pInfo);
   pGFpx = (IppsGFpState*)( IPP_ALIGNED_PTR(pGFpx, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGFpx), ippStsContextMatchErr );

   pInfo->pBasicGF = cpGFpBasic(pGFpx);
   pInfo->pGroundGF = GFP_GROUNDGF(pGFpx);
   pInfo->basicGFdegree = cpGFpBasicDegreeExtension(pGFpx);
   pInfo->groundGFdegree = GFP_DEGREE(pGFpx);
   pInfo->elementLen = GFP_FELEN32(pGFpx);

   return ippStsNoErr;
}
#endif
