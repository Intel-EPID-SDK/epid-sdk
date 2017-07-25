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
//     Intel(R) Performance Primitives. Cryptography Primitives.
//     GF(p^d) methods, if binomial generator
//
*/
#include "owndefs.h"
#include "owncp.h"

#include "pcpgfpxstuff.h"
#include "pcpgfpxmethod_com.h"

static BNU_CHUNK_T* cpGFpxMul_G0(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFpx)
{
   IppsGFpState* pGroundGF = GFP_GROUNDGF(pGFpx);
   BNU_CHUNK_T* pGFpolynomial = GFP_MODULUS(pGFpx); /* g(x) = t^d + g0 */
#if defined GS_DBG
   BNU_CHUNK_T* arg0 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* arg1 = cpGFpGetPool(1, pGroundGF);
   int groundElemLen = GFP_FELEN(pGroundGF);
#endif
   //return pGroundGF->mul(pR, pA, pGFpolynomial, GFP_GROUNDGF(pGFpx));
#if defined GS_DBG
   cpGFpxGet(arg0, groundElemLen, pA, pGroundGF);
   cpGFpxGet(arg1, groundElemLen, pGFpolynomial, pGroundGF);
#endif
   pGroundGF->mul(pR, pA, pGFpolynomial, GFP_GROUNDGF(pGFpx));
#if defined GS_DBG
   cpGFpReleasePool(2, pGroundGF);
#endif
   return pR;
}

/*
// Multiplication in GF(p^2), if field polynomial: g(x) = t^2 + beta  => binominal
*/
BNU_CHUNK_T* cpGFpxMul_p2_binom(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGFpx)
{
   IppsGFpState* pGroundGF = GFP_GROUNDGF(pGFpx);
   int groundElemLen = GFP_FELEN(pGroundGF);

   const BNU_CHUNK_T* pA0 = pA;
   const BNU_CHUNK_T* pA1 = pA+groundElemLen;

   const BNU_CHUNK_T* pB0 = pB;
   const BNU_CHUNK_T* pB1 = pB+groundElemLen;

   BNU_CHUNK_T* pR0 = pR;
   BNU_CHUNK_T* pR1 = pR+groundElemLen;

   BNU_CHUNK_T* t0 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* t1 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* t2 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* t3 = cpGFpGetPool(1, pGroundGF);
#if defined GS_DBG
   BNU_CHUNK_T* arg0 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* arg1 = cpGFpGetPool(1, pGroundGF);
#endif

#if defined GS_DBG
   cpGFpxGet(arg0, groundElemLen, pA0, pGroundGF);
   cpGFpxGet(arg1, groundElemLen, pB0, pGroundGF);
#endif
   pGroundGF->mul(t0, pA0, pB0, pGroundGF);    /* t0 = a[0]*b[0] */
#if defined GS_DBG
   cpGFpxGet(arg0, groundElemLen, pA1, pGroundGF);
   cpGFpxGet(arg1, groundElemLen, pB1, pGroundGF);
#endif
   pGroundGF->mul(t1, pA1, pB1, pGroundGF);    /* t1 = a[1]*b[1] */
   pGroundGF->add(t2, pA0, pA1, pGroundGF);    /* t2 = a[0]+a[1] */
   pGroundGF->add(t3, pB0, pB1, pGroundGF);    /* t3 = b[0]+b[1] */

#if defined GS_DBG
   cpGFpxGet(arg0, groundElemLen, t2, pGroundGF);
   cpGFpxGet(arg1, groundElemLen, t3, pGroundGF);
#endif
   pGroundGF->mul(pR1, t2,  t3, pGroundGF);    /* r[1] = (a[0]+a[1]) * (b[0]+b[1]) */
   pGroundGF->sub(pR1, pR1, t0, pGroundGF);    /* r[1] -= a[0]*b[0]) + a[1]*b[1] */
   pGroundGF->sub(pR1, pR1, t1, pGroundGF);

   cpGFpxMul_G0(t1, t1, pGFpx);
   pGroundGF->sub(pR0, t0, t1, pGroundGF);

#if defined GS_DBG
   cpGFpReleasePool(2, pGroundGF);
#endif
   cpGFpReleasePool(4, pGroundGF);
   return pR;
}

/*
// Squaring in GF(p^2), if field polynomial: g(x) = t^2 + beta  => binominal
*/
BNU_CHUNK_T* cpGFpxSqr_p2_binom(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFpx)
{
   IppsGFpState* pGroundGF = GFP_GROUNDGF(pGFpx);
   int groundElemLen = GFP_FELEN(pGroundGF);

   const BNU_CHUNK_T* pA0 = pA;
   const BNU_CHUNK_T* pA1 = pA+groundElemLen;

   BNU_CHUNK_T* pR0 = pR;
   BNU_CHUNK_T* pR1 = pR+groundElemLen;

   BNU_CHUNK_T* t0 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* t1 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* u0 = cpGFpGetPool(1, pGroundGF);
#if defined GS_DBG
   BNU_CHUNK_T* arg0 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* arg1 = cpGFpGetPool(1, pGroundGF);
#endif

#if defined GS_DBG
   cpGFpxGet(arg0, groundElemLen, pA0, pGroundGF);
   cpGFpxGet(arg1, groundElemLen, pA1, pGroundGF);
#endif
   pGroundGF->mul(u0, pA0, pA1, pGroundGF); /* u0 = a[0]*a[1] */
   pGroundGF->sqr(t0, pA0, pGroundGF);      /* t0 = a[0]*a[0] */
   pGroundGF->sqr(t1, pA1, pGroundGF);      /* t1 = a[1]*a[1] */
   cpGFpxMul_G0(t1, t1, pGFpx);
   pGroundGF->sub(pR0, t0, t1, pGroundGF);
   pGroundGF->add(pR1, u0, u0, pGroundGF);  /* r[1] = 2*a[0]*a[1] */

#if defined GS_DBG
   cpGFpReleasePool(2, pGroundGF);
#endif
   cpGFpReleasePool(3, pGroundGF);
   return pR;
}

/*
// returns methods
*/
IPPFUN( const IppsGFpMethod*, ippsGFpxMethod_binom2, (void) )
{
   static IppsGFpMethod method = {
      cpGFpxAdd_com,
      cpGFpxSub_com,
      cpGFpxNeg_com,
      cpGFpxDiv2_com,
      cpGFpxMul2_com,
      cpGFpxMul3_com,
      cpGFpxMul_p2_binom,
      cpGFpxSqr_p2_binom,
      cpGFpxEncode_com,
      cpGFpxDecode_com
   };
   return &method;
}


/*
// Multiplication in GF(p^3), if field polynomial: g(x) = t^2 + beta  => binominal
*/
BNU_CHUNK_T* cpGFpxMul_p3_binom(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGFpx)
{
   IppsGFpState* pGroundGF = GFP_GROUNDGF(pGFpx);
   int groundElemLen = GFP_FELEN(pGroundGF);

   const BNU_CHUNK_T* pA0 = pA;
   const BNU_CHUNK_T* pA1 = pA+groundElemLen;
   const BNU_CHUNK_T* pA2 = pA+groundElemLen*2;

   const BNU_CHUNK_T* pB0 = pB;
   const BNU_CHUNK_T* pB1 = pB+groundElemLen;
   const BNU_CHUNK_T* pB2 = pB+groundElemLen*2;

   BNU_CHUNK_T* pR0 = pR;
   BNU_CHUNK_T* pR1 = pR+groundElemLen;
   BNU_CHUNK_T* pR2 = pR+groundElemLen*2;

   BNU_CHUNK_T* t0 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* t1 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* t2 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* u0 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* u1 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* u2 = cpGFpGetPool(1, pGroundGF);

   pGroundGF->add(u0 ,pA0, pA1, pGroundGF);    /* u0 = a[0]+a[1] */
   pGroundGF->add(t0 ,pB0, pB1, pGroundGF);    /* t0 = b[0]+b[1] */
   pGroundGF->mul(u0, u0,  t0,  pGroundGF);    /* u0 = (a[0]+a[1])*(b[0]+b[1]) */
   pGroundGF->mul(t0, pA0, pB0, pGroundGF);    /* t0 = a[0]*b[0] */

   pGroundGF->add(u1 ,pA1, pA2, pGroundGF);    /* u1 = a[1]+a[2] */
   pGroundGF->add(t1 ,pB1, pB2, pGroundGF);    /* t1 = b[1]+b[2] */
   pGroundGF->mul(u1, u1,  t1,  pGroundGF);    /* u1 = (a[1]+a[2])*(b[1]+b[2]) */
   pGroundGF->mul(t1, pA1, pB1, pGroundGF);    /* t1 = a[1]*b[1] */

   pGroundGF->add(u2 ,pA2, pA0, pGroundGF);    /* u2 = a[2]+a[0] */
   pGroundGF->add(t2 ,pB2, pB0, pGroundGF);    /* t2 = b[2]+b[0] */
   pGroundGF->mul(u2, u2,  t2,  pGroundGF);    /* u2 = (a[2]+a[0])*(b[2]+b[0]) */
   pGroundGF->mul(t2, pA2, pB2, pGroundGF);    /* t2 = a[2]*b[2] */

   pGroundGF->sub(u0, u0,  t0,  pGroundGF);    /* u0 = a[0]*b[1]+a[1]*b[0] */
   pGroundGF->sub(u0, u0,  t1,  pGroundGF);
   pGroundGF->sub(u1, u1,  t1,  pGroundGF);    /* u1 = a[1]*b[2]+a[2]*b[1] */
   pGroundGF->sub(u1, u1,  t2,  pGroundGF);
   pGroundGF->sub(u2, u2,  t2,  pGroundGF);    /* u2 = a[2]*b[0]+a[0]*b[2] */
   pGroundGF->sub(u2, u2,  t0,  pGroundGF);

   cpGFpxMul_G0(u1, u1, pGFpx);                /* u1 = (a[1]*b[2]+a[2]*b[1]) * beta */
   cpGFpxMul_G0(t2, t2, pGFpx);                /* t2 = a[2]*b[2] * beta */

   pGroundGF->sub(pR0, t0, u1,  pGroundGF);    /* r[0] = a[0]*b[0] - (a[2]*b[1]+a[1]*b[2])*beta */
   pGroundGF->sub(pR1, u0, t2,  pGroundGF);    /* r[1] = a[1]*b[0] + a[0]*b[1] - a[2]*b[2]*beta */

   pGroundGF->add(pR2, u2, t1,  pGroundGF);     /* r[2] = a[2]*b[0] + a[1]*b[1] + a[0]*b[2] */

   cpGFpReleasePool(6, pGroundGF);
   return pR;
}

/*
// Squaring in GF(p^3), if field polynomial: g(x) = t^2 + beta  => binominal
*/
BNU_CHUNK_T* cpGFpxSqr_p3_binom(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFpx)
{
   IppsGFpState* pGroundGF = GFP_GROUNDGF(pGFpx);
   int groundElemLen = GFP_FELEN(pGroundGF);

   const BNU_CHUNK_T* pA0 = pA;
   const BNU_CHUNK_T* pA1 = pA+groundElemLen;
   const BNU_CHUNK_T* pA2 = pA+groundElemLen*2;

   BNU_CHUNK_T* pR0 = pR;
   BNU_CHUNK_T* pR1 = pR+groundElemLen;
   BNU_CHUNK_T* pR2 = pR+groundElemLen*2;

   BNU_CHUNK_T* s0 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* s1 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* s2 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* s3 = cpGFpGetPool(1, pGroundGF);
   BNU_CHUNK_T* s4 = cpGFpGetPool(1, pGroundGF);

   pGroundGF->add(s2, pA0, pA2, pGroundGF);
   pGroundGF->sub(s2,  s2, pA1, pGroundGF);
   pGroundGF->sqr(s2,  s2, pGroundGF);
   pGroundGF->sqr(s0, pA0, pGroundGF);
   pGroundGF->sqr(s4, pA2, pGroundGF);
   pGroundGF->mul(s1, pA0, pA1, pGroundGF);
   pGroundGF->mul(s3, pA1, pA2, pGroundGF);
   pGroundGF->add(s1,  s1,  s1, pGroundGF);
   pGroundGF->add(s3,  s3,  s3, pGroundGF);

   pGroundGF->add(pR2,  s1, s2, pGroundGF);
   pGroundGF->add(pR2, pR2, s3, pGroundGF);
   pGroundGF->sub(pR2, pR2, s0, pGroundGF);
   pGroundGF->sub(pR2, pR2, s4, pGroundGF);

   cpGFpxMul_G0(s4, s4, pGFpx);
   pGroundGF->sub(pR1, s1,  s4, pGroundGF);

   cpGFpxMul_G0(s3, s3, pGFpx);
   pGroundGF->sub(pR0, s0,  s3, pGroundGF);

   cpGFpReleasePool(5, pGroundGF);
   return pR;
}


/*
// returns methods
*/
IPPFUN( const IppsGFpMethod*, ippsGFpxMethod_binom3, (void) )
{
   static IppsGFpMethod method = {
      cpGFpxAdd_com,
      cpGFpxSub_com,
      cpGFpxNeg_com,
      cpGFpxDiv2_com,
      cpGFpxMul2_com,
      cpGFpxMul3_com,
      cpGFpxMul_p3_binom,
      cpGFpxSqr_p3_binom,
      cpGFpxEncode_com,
      cpGFpxDecode_com
   };
   return &method;
}


/*
// Multiplication in GF(p^d), if field polynomial: g(x) = t^d + beta  => binominal
*/
BNU_CHUNK_T* cpGFpxMul_pd_binom(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGFpx)
{
   BNU_CHUNK_T* pGFpolynomial = GFP_MODULUS(pGFpx);
   int deg = GFP_DEGREE(pGFpx);
   int elemLen= GFP_FELEN(pGFpx);
   int groundElemLen = GFP_FELEN(GFP_GROUNDGF(pGFpx));
   int d;

   BNU_CHUNK_T* R = cpGFpGetPool(1, pGFpx);
   BNU_CHUNK_T* X = cpGFpGetPool(1, pGFpx);
   BNU_CHUNK_T* T = cpGFpGetPool(2, pGFpx);
   BNU_CHUNK_T* T0= T;
   BNU_CHUNK_T* T1= T+elemLen;

   /* T0 = A * beta */
   cpGFpxMul_GFE(T0, pA, pGFpolynomial, pGFpx);
   /* T1 = A */
   cpGFpElementCopy(T1, pA, elemLen);

   /* R = A * B[0] */
   cpGFpxMul_GFE(R, pA, pB, pGFpx);

   /* R += (A*B[d]) mod g() */
   for(d=1; d<deg; d++) {
      cpGFpxMul_GFE(X, GFPX_IDX_ELEMENT(T0, deg-d, groundElemLen), GFPX_IDX_ELEMENT(pB, d, groundElemLen),  pGFpx);
      pGFpx->add(R, R, X, pGFpx);
   }
   cpGFpElementCopy(pR, R, elemLen);

   cpGFpReleasePool(4, pGFpx);
   return pR;
}

/*
// Squaring in GF(p^d), if field polynomial: g(x) = t^d + beta  => binominal
*/
BNU_CHUNK_T* cpGFpxSqr_pd_binom(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFpx)
{
   return cpGFpxMul_pd_binom(pR, pA, pA, pGFpx);
}

/*
// returns methods
*/
IPPFUN( const IppsGFpMethod*, ippsGFpxMethod_binom, (void) )
{
   static IppsGFpMethod method = {
      cpGFpxAdd_com,
      cpGFpxSub_com,
      cpGFpxNeg_com,
      cpGFpxDiv2_com,
      cpGFpxMul2_com,
      cpGFpxMul3_com,
      cpGFpxMul_pd_binom,
      cpGFpxSqr_pd_binom,
      cpGFpxEncode_com,
      cpGFpxDecode_com
   };
   return &method;
}
