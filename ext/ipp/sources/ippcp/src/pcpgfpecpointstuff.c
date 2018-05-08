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
//     Intel(R) Performance Primitives. Cryptography Primitives.
//     Internal EC over GF(p^m) basic Definitions & Function Prototypes
// 
//     Context:
//        gfec_MakePoint()
//        gfec_SetPoint
//        gfec_GetPoint
// 
//        gfec_ComparePoint()
//        gfec_IsPointOnCurve()
// 
//        gfec_NegPoint()
//        gfec_DblPoint()
//        gfec_AddPoint()
//        gfec_MulPoint()
// 
// 
// 
*/

#include "owndefs.h"
#include "owncp.h"

#include "pcpgfpecstuff.h"
#include "gsscramble.h"


int gfec_MakePoint(IppsGFpECPoint* pPoint, const BNU_CHUNK_T* pElm, IppsGFpECState* pEC)
{
   IppsGFpState* pGF = ECP_GFP(pEC);
   gsModEngine* pGFE = GFP_PMA(pGF);
   int elemLen = GFP_FELEN(pGFE);

   mod_mul mulF = GFP_METHOD(pGFE)->mul;
   mod_sqr sqrF = GFP_METHOD(pGFE)->sqr;
   mod_add addF = GFP_METHOD(pGFE)->add;

   BNU_CHUNK_T* pX = ECP_POINT_X(pPoint);
   BNU_CHUNK_T* pY = ECP_POINT_Y(pPoint);
   BNU_CHUNK_T* pZ = ECP_POINT_Z(pPoint);

   /* set x-coordinate */
   cpGFpElementCopy(pX, pElm, elemLen);

   /* T = X^3 + A*X + B */
   sqrF(pY, pX, pGFE);
   mulF(pY, pY, pX, pGFE);
   if(ECP_SPECIFIC(pEC)!=ECP_EPID2) {
      mulF(pZ, ECP_A(pEC), pX, pGFE);
      addF(pY, pY, pZ, pGFE);
   }
   addF(pY, pY, ECP_B(pEC), pGFE);

   /* set z-coordinate =1 */
   cpGFpElementCopyPadd(pZ, elemLen, GFP_MNT_R(pGFE), elemLen);

   /* Y = sqrt(Y) */
   if( cpGFpSqrt(pY, pY, pGFE) ) {
      ECP_POINT_FLAGS(pPoint) = ECP_AFFINE_POINT | ECP_FINITE_POINT;
      return 1;
   }
   else {
      gfec_SetPointAtInfinity(pPoint);
      return 0;
   }
}

static int gfec_IsAffinePointAtInfinity(int ecInfinity,
                           const BNU_CHUNK_T* pX, const BNU_CHUNK_T* pY,
                           const IppsGFpState* pGF)
{
   gsModEngine* pGFE = GFP_PMA(pGF);
   int elmLen = GFP_FELEN(pGFE);

   int atInfinity = GFP_IS_ZERO(pX,elmLen);

   BNU_CHUNK_T* tmpY = cpGFpGetPool(1, pGFE);

   /* set tmpY either:
   // 0,       if ec.b !=0
   // mont(1)  if ec.b ==0
   */
   cpGFpElementPadd(tmpY, elmLen, 0);
   if(ecInfinity) {
      gsModEngine* pBasicGFE = cpGFpBasic(pGFE);
      int basicElmLen = GFP_FELEN(pBasicGFE);
      BNU_CHUNK_T* mont1 = GFP_MNT_R(pBasicGFE);
      cpGFpElementCopyPadd(tmpY, elmLen, mont1, basicElmLen);
   }

   /* check if (x,y) represents point at infinity */
   atInfinity &= GFP_EQ(pY, tmpY, elmLen);

   cpGFpReleasePool(1, pGFE);
   return atInfinity;
}

/* returns: 1/0 if set up finite/infinite point */
int gfec_SetPoint(BNU_CHUNK_T* pPointData,
            const BNU_CHUNK_T* pX, const BNU_CHUNK_T* pY,
                  IppsGFpECState* pEC)
{
   IppsGFpState* pGF = ECP_GFP(pEC);
   gsModEngine* pGFE = GFP_PMA(pGF);
   int elmLen = GFP_FELEN(pGFE);

   int finite_point= !gfec_IsAffinePointAtInfinity(ECP_INFINITY(pEC), pX, pY, pGF);
   if(finite_point) {
      gsModEngine* pBasicGFE = cpGFpBasic(pGFE);
      cpGFpElementCopy(pPointData, pX, elmLen);
      cpGFpElementCopy(pPointData+elmLen, pY, elmLen);
      cpGFpElementCopyPadd(pPointData+elmLen*2, elmLen, GFP_MNT_R(pBasicGFE), GFP_FELEN(pBasicGFE));
   }
   else
      cpGFpElementPadd(pPointData, 3*elmLen, 0);

   return finite_point;
}


#if ( ECP_PROJECTIVE_COORD == JACOBIAN )
/* returns 1/0 if point is finite/infinite */
int gfec_GetPoint(BNU_CHUNK_T* pX, BNU_CHUNK_T* pY, const IppsGFpECPoint* pPoint, IppsGFpECState* pEC)
{
   IppsGFpState* pGF = ECP_GFP(pEC);
   gsModEngine* pGFE = GFP_PMA(pGF);
   int elemLen = GFP_FELEN(pGFE);

   if( !IS_ECP_FINITE_POINT(pPoint) ) {
      if(pX) cpGFpElementPadd(pX, elemLen, 0);
      if(pY) cpGFpElementPadd(pY, elemLen, 0);
      return 0;
   }

   /* affine point (1==Z) */
   if( IS_ECP_AFFINE_POINT(pPoint) ) {
      if(pX)
         cpGFpElementCopy(pX, ECP_POINT_X(pPoint), elemLen);
      if(pY)
         cpGFpElementCopy(pY, ECP_POINT_Y(pPoint), elemLen);
      return 1;
   }

   /* projective point (1!=Z) */
   {
      mod_mul mulF = GFP_METHOD(pGFE)->mul;
      mod_sqr sqrF = GFP_METHOD(pGFE)->sqr;

      /* T = (1/Z)*(1/Z) */
      BNU_CHUNK_T* pT    = cpGFpGetPool(1, pGFE);
      BNU_CHUNK_T* pZinv = cpGFpGetPool(1, pGFE);
      BNU_CHUNK_T* pU = cpGFpGetPool(1, pGFE);
      cpGFpxInv(pZinv, ECP_POINT_Z(pPoint), pGFE);
      sqrF(pT, pZinv, pGFE);

      if(pX) {
         mulF(pU, ECP_POINT_X(pPoint), pT, pGFE);
         cpGFpElementCopy(pX, pU, elemLen);
      }
      if(pY) {
         mulF(pT, pZinv, pT, pGFE);
         mulF(pU, ECP_POINT_Y(pPoint), pT, pGFE);
         cpGFpElementCopy(pY, pU, elemLen);
      }

      cpGFpReleasePool(3, pGFE);
      return 1;
   }
}
#endif


#if ( ECP_PROJECTIVE_COORD == JACOBIAN )
int gfec_ComparePoint(const IppsGFpECPoint* pP, const IppsGFpECPoint* pQ, IppsGFpECState* pEC)
{
   IppsGFpState* pGF = ECP_GFP(pEC);
   gsModEngine* pGFE = GFP_PMA(pGF);
   int elemLen = GFP_FELEN(pGFE);

   /* P or/and Q at Infinity */
   if( !IS_ECP_FINITE_POINT(pP) )
      return !IS_ECP_FINITE_POINT(pQ)? 1:0;
   if( !IS_ECP_FINITE_POINT(pQ) )
      return !IS_ECP_FINITE_POINT(pP)? 1:0;

   /* Px==Qx && Py==Qy && Pz==Qz */
   if(  GFP_EQ(ECP_POINT_Z(pP), ECP_POINT_Z(pQ), elemLen)
      &&GFP_EQ(ECP_POINT_X(pP), ECP_POINT_X(pQ), elemLen)
      &&GFP_EQ(ECP_POINT_Y(pP), ECP_POINT_Y(pQ), elemLen))
      return 1;

   else {
      mod_mul mulF = GFP_METHOD(pGFE)->mul;
      mod_sqr sqrF = GFP_METHOD(pGFE)->sqr;

      int isEqu = 1;

      BNU_CHUNK_T* pPtmp = cpGFpGetPool(1, pGFE);
      BNU_CHUNK_T* pQtmp = cpGFpGetPool(1, pGFE);
      BNU_CHUNK_T* pPz   = cpGFpGetPool(1, pGFE);
      BNU_CHUNK_T* pQz   = cpGFpGetPool(1, pGFE);

      if(isEqu) {
         /* Px*Qz^2 ~ Qx*Pz^2 */
         if( IS_ECP_AFFINE_POINT(pQ) ) /* Ptmp = Px * Qz^2 */
            cpGFpElementCopy(pPtmp, ECP_POINT_X(pP), elemLen);
         else {
            sqrF(pQz, ECP_POINT_Z(pQ), pGFE);
            mulF(pPtmp, ECP_POINT_X(pP), pQz, pGFE);
         }
         if( IS_ECP_AFFINE_POINT(pP) ) /* Qtmp = Qx * Pz^2 */
            cpGFpElementCopy(pQtmp, ECP_POINT_X(pQ), elemLen);
         else {
            sqrF(pPz, ECP_POINT_Z(pP), pGFE);
            mulF(pQtmp, ECP_POINT_X(pQ), pPz, pGFE);
         }
         isEqu = GFP_EQ(pPtmp, pQtmp, elemLen);
      }

      if(isEqu) {
         /* Py*Qz^3 ~ Qy*Pz^3 */
         if( IS_ECP_AFFINE_POINT(pQ) ) /* Ptmp = Py * Qz^3 */
            cpGFpElementCopy(pPtmp, ECP_POINT_Y(pP), elemLen);
         else {
            mulF(pQz, ECP_POINT_Z(pQ), pQz, pGFE);
            mulF(pPtmp, pQz, ECP_POINT_Y(pP), pGFE);
         }
         if( IS_ECP_AFFINE_POINT(pP) ) /* Qtmp = Qy * Pz^3 */
            cpGFpElementCopy(pQtmp, ECP_POINT_Y(pQ), elemLen);
         else {
            mulF(pPz, ECP_POINT_Z(pP), pPz, pGFE);
            mulF(pQtmp, pPz, ECP_POINT_Y(pQ), pGFE);
         }
         isEqu = GFP_EQ(pPtmp, pQtmp, elemLen);
      }

      cpGFpReleasePool(4, pGFE);
      return isEqu;
   }
}
#endif


#if ( ECP_PROJECTIVE_COORD == JACOBIAN )
int gfec_IsPointOnCurve(const IppsGFpECPoint* pPoint, IppsGFpECState* pEC)
{
   /* point at infinity does not belong curve */
   if( !IS_ECP_FINITE_POINT(pPoint) )
      //return 1;
      return 0;

   /* test that 0 == R = (Y^2) - (X^3 + A*X*(Z^4) + B*(Z^6)) */
   else {
      int isOnCurve = 0;

      IppsGFpState* pGF = ECP_GFP(pEC);
      gsModEngine* pGFE = GFP_PMA(pGF);

      mod_mul mulF = GFP_METHOD(pGFE)->mul;
      mod_sqr sqrF = GFP_METHOD(pGFE)->sqr;
      mod_sub subF = GFP_METHOD(pGFE)->sub;

      BNU_CHUNK_T* pX = ECP_POINT_X(pPoint);
      BNU_CHUNK_T* pY = ECP_POINT_Y(pPoint);
      BNU_CHUNK_T* pZ = ECP_POINT_Z(pPoint);

      BNU_CHUNK_T* pR = cpGFpGetPool(1, pGFE);
      BNU_CHUNK_T* pT = cpGFpGetPool(1, pGFE);

      sqrF(pR, pY, pGFE);       /* R = Y^2 */
      sqrF(pT, pX, pGFE);       /* T = X^3 */
      mulF(pT, pX, pT, pGFE);
      subF(pR, pR, pT, pGFE);   /* R -= T */

      if( IS_ECP_AFFINE_POINT(pPoint) ) {
         mulF(pT, pX, ECP_A(pEC), pGFE);   /* T = A*X */
         subF(pR, pR, pT, pGFE);               /* R -= T */
         subF(pR, pR, ECP_B(pEC), pGFE);       /* R -= B */
      }
      else {
         BNU_CHUNK_T* pZ4 = cpGFpGetPool(1, pGFE);
         BNU_CHUNK_T* pZ6 = cpGFpGetPool(1, pGFE);

         sqrF(pZ6, pZ, pGFE);         /* Z^2 */
         sqrF(pZ4, pZ6, pGFE);        /* Z^4 */
         mulF(pZ6, pZ6, pZ4, pGFE);   /* Z^6 */

         mulF(pZ4, pZ4, pX, pGFE);         /* X*(Z^4) */
         mulF(pZ4, pZ4, ECP_A(pEC), pGFE); /* A*X*(Z^4) */
         mulF(pZ6, pZ6, ECP_B(pEC), pGFE); /* B*(Z^4) */

         subF(pR, pR, pZ4, pGFE);           /* R -= A*X*(Z^4) */
         subF(pR, pR, pZ6, pGFE);           /* R -= B*(Z^6)   */

         cpGFpReleasePool(2, pGFE);
      }

      isOnCurve = GFP_IS_ZERO(pR, GFP_FELEN(pGFE));
      cpGFpReleasePool(2, pGFE);
      return isOnCurve;
   }
}
#endif

IppsGFpECPoint* gfec_NegPoint(IppsGFpECPoint* pR,
                        const IppsGFpECPoint* pP, IppsGFpECState* pEC)
{
   IppsGFpState* pGF = ECP_GFP(pEC);
   gsModEngine* pGFE = GFP_PMA(pGF);
   int elmLen = GFP_FELEN(pGFE);
   if(pR!=pP)
      gfec_CopyPoint(pR, pP, elmLen);
   GFP_METHOD(pGFE)->neg(ECP_POINT_Y(pR), ECP_POINT_Y(pP), pGFE);
   return pR;
}


#if ( ECP_PROJECTIVE_COORD == JACOBIAN )
/*
// A = 4*x*y^2
// B = 3*x^2 + a*z^4
//
// x3 = -2*A + B^2
// y3 = -8y^4 +B*(A-x3)
// z3 = 2*y*z
//
// complexity: = 4s+4m (NIST's, SM2 curves)
//             = (EPID2 curve)
//             = 6s+4m (arbitrary curves)
*/
static void gfec_point_double(BNU_CHUNK_T* pRdata, const BNU_CHUNK_T* pPdata, IppsGFpECState* pEC)
{
   IppsGFpState* pGF = ECP_GFP(pEC);
   gsModEngine* pGFE = GFP_PMA(pGF);
   int elemLen = GFP_FELEN(pGFE);

   mod_add  add = GFP_METHOD(pGFE)->add;   /* gf add  */
   mod_sub  sub = GFP_METHOD(pGFE)->sub;   /* gf sub  */
   mod_div2 div2= GFP_METHOD(pGFE)->div2;  /* gf div2 */
   mod_mul2 mul2= GFP_METHOD(pGFE)->mul2;  /* gf mul2 */
   mod_mul3 mul3= GFP_METHOD(pGFE)->mul3;  /* gf mul3 */
   mod_mul  mul = GFP_METHOD(pGFE)->mul;   /* gf mul  */
   mod_sqr  sqr = GFP_METHOD(pGFE)->sqr;   /* gf sqr  */

   const BNU_CHUNK_T* pX = pPdata;
   const BNU_CHUNK_T* pY = pPdata+elemLen;
   const BNU_CHUNK_T* pZ = pPdata+2*+elemLen;

   BNU_CHUNK_T* rX = pRdata;
   BNU_CHUNK_T* rY = pRdata+elemLen;
   BNU_CHUNK_T* rZ = pRdata+2*elemLen;

   /* get temporary from top of EC point pool */
   BNU_CHUNK_T* U = pEC->pPool;
   BNU_CHUNK_T* M = U+elemLen;
   BNU_CHUNK_T* S = M+elemLen;

   mul2(S, pY, pGFE);            /* S = 2*Y */
   sqr(U, pZ, pGFE);             /* U = Z^2 */

   sqr(M, S, pGFE);              /* M = 4*Y^2 */
   mul(rZ, S, pZ, pGFE);         /* Zres = 2*Y*Z */

   sqr(rY, M, pGFE);             /* Yres = 16*Y^4 */

   mul(S, M, pX, pGFE);          /* S = 4*X*Y^2 */
   div2(rY, rY, pGFE);           /* Yres =  8*Y^4 */

   if(ECP_STD==ECP_SPECIFIC(pEC)) {
      add(M, pX, U, pGFE);       /* M = 3*(X^2-Z^4) */
      sub(U, pX, U, pGFE);
      mul(M, M, U, pGFE);
      mul3(M, M, pGFE);
   }
   else {
      sqr(M, pX, pGFE);          /* M = 3*X^2 */
      mul3(M, M, pGFE);
      if(ECP_EPID2!=ECP_SPECIFIC(pEC)) {
         sqr(U, U, pGFE);        /* M = 3*X^2+a*Z4 */
         mul(U, U, ECP_A(pEC), pGFE);
         add(M, M, U, pGFE);
      }
   }

   mul2(U, S, pGFE);             /* U = 8*X*Y^2 */
   sqr(rX, M, pGFE);             /* Xres = M^2 */
   sub(rX, rX, U, pGFE);         /* Xres = M^2-U */

   sub(S, S, rX, pGFE);          /* S = 4*X*Y^2-Xres */
   mul(S, S, M, pGFE);           /* S = M*(4*X*Y^2-Xres) */
   sub(rY, S, rY, pGFE);         /* Yres = M*(4*X*Y^2-Xres) -8*Y^4 */
}
#endif

IppsGFpECPoint* gfec_DblPoint(IppsGFpECPoint* pR,
                        const IppsGFpECPoint* pP, IppsGFpECState* pEC)
{
   gfec_point_double(ECP_POINT_X(pR), ECP_POINT_X(pP), pEC);
   ECP_POINT_FLAGS(pR) = gfec_IsPointAtInfinity(pR)? 0 : ECP_FINITE_POINT;
   return pR;
}


#if ( ECP_PROJECTIVE_COORD == JACOBIAN )
/*
// S1 = y1*z2^3
// S2 = y2*z1^3
//
// U1 = x1*z2^2
// U2 = x2*z1^2

//  R = S2-S1
//  H = U2-U1
//
//  x3 = -H^3 -2*U1*H^2 +R2
//  y3 = -S1*H^3 +R*(U1*H^2 -x3)
//  z3 = z1*z2*H
//
// complexity = 4s+12m
*/
static void gfec_point_add(BNU_CHUNK_T* pRdata, const BNU_CHUNK_T* pPdata, const BNU_CHUNK_T* pQdata, IppsGFpECState* pEC)
{
   IppsGFpState* pGF = ECP_GFP(pEC);
   gsModEngine* pGFE = GFP_PMA(pGF);
   int elemLen = GFP_FELEN(pGFE);

   mod_sub  sub = GFP_METHOD(pGFE)->sub;   /* gf sub  */
   mod_mul2 mul2= GFP_METHOD(pGFE)->mul2;  /* gf mul2 */
   mod_mul  mul = GFP_METHOD(pGFE)->mul;   /* gf mul  */
   mod_sqr  sqr = GFP_METHOD(pGFE)->sqr;   /* gf sqr  */

   /* coordinates of P */
   const BNU_CHUNK_T* px1 = pPdata;
   const BNU_CHUNK_T* py1 = pPdata+elemLen;
   const BNU_CHUNK_T* pz1 = pPdata+2*elemLen;

   /* coordinates of Q */
   const BNU_CHUNK_T* px2 = pQdata;
   const BNU_CHUNK_T* py2 = pQdata+elemLen;
   const BNU_CHUNK_T* pz2 = pQdata+2*elemLen;

   int inftyP = GFP_IS_ZERO(pz1, elemLen);
   int inftyQ = GFP_IS_ZERO(pz2, elemLen);

   /* get temporary from top of EC point pool */
   BNU_CHUNK_T* U1 = pEC->pPool;
   BNU_CHUNK_T* U2 = U1 + elemLen;
   BNU_CHUNK_T* S1 = U2 + elemLen;
   BNU_CHUNK_T* S2 = S1 + elemLen;
   BNU_CHUNK_T* H  = S2 + elemLen;
   BNU_CHUNK_T* R  = H  + elemLen;

   BNU_CHUNK_T* pRx = R  + elemLen; /* temporary result */
   BNU_CHUNK_T* pRy = pRx+ elemLen;
   BNU_CHUNK_T* pRz = pRy+ elemLen;

   mul(S1, py1, pz2, pGFE);       // S1 = Y1*Z2
   sqr(U1, pz2, pGFE);            // U1 = Z2^2

   mul(S2, py2, pz1, pGFE);       // S2 = Y2*Z1
   sqr(U2, pz1, pGFE);            // U2 = Z1^2

   mul(S1, S1, U1, pGFE);         // S1 = Y1*Z2^3
   mul(S2, S2, U2, pGFE);         // S2 = Y2*Z1^3

   mul(U1, px1, U1, pGFE);        // U1 = X1*Z2^2
   mul(U2, px2, U2, pGFE);        // U2 = X2*Z1^2

   sub(R, S2, S1, pGFE);          // R = S2-S1
   sub(H, U2, U1, pGFE);          // H = U2-U1

   if( GFP_IS_ZERO(H, elemLen) && !inftyP && !inftyQ ) {
      if( GFP_IS_ZERO(R, elemLen) )
         gfec_point_double(pRdata, pPdata, pEC);
      else
         cpGFpElementPadd(pRdata, 3*elemLen, 0);
      return;
   }

   mul(pRz, pz1, pz2, pGFE);      // Z3 = Z1*Z2
   sqr(U2, H, pGFE);              // U2 = H^2
   mul(pRz, pRz, H, pGFE);        // Z3 = (Z1*Z2)*H
   sqr(S2, R, pGFE);              // S2 = R^2
   mul(H, H, U2, pGFE);           // H = H^3

   mul(U1, U1, U2, pGFE);         // U1 = U1*H^2
   sub(pRx, S2, H, pGFE);         // X3 = R^2 - H^3
   mul2(U2, U1, pGFE);            // U2 = 2*U1*H^2
   mul(S1, S1, H, pGFE);          // S1 = S1*H^3
   sub(pRx, pRx, U2, pGFE);       // X3 = (R^2 - H^3) -2*U1*H^2

   sub(pRy, U1, pRx, pGFE);       // Y3 = R*(U1*H^2 - X3) -S1*H^3
   mul(pRy, pRy, R, pGFE);
   sub(pRy, pRy, S1, pGFE);

   cpMaskMove(pRx, px2, elemLen*3, inftyP);
   cpMaskMove(pRx, px1, elemLen*3, inftyQ);

   cpGFpElementCopy(pRdata, pRx, 3*elemLen);
}

/*
// complexity = 3s+8m
*/
static void gfec_affine_point_add(BNU_CHUNK_T* pRdata, const BNU_CHUNK_T* pPdata, const BNU_CHUNK_T* pAdata, IppsGFpECState* pEC)
{
   IppsGFpState* pGF = ECP_GFP(pEC);
   gsModEngine* pGFE = GFP_PMA(pGF);
   int elemLen = GFP_FELEN(pGFE);

   mod_sub  sub = GFP_METHOD(pGFE)->sub;   /* gf sub  */
   mod_mul2 mul2= GFP_METHOD(pGFE)->mul2;  /* gf mul2 */
   mod_mul  mul = GFP_METHOD(pGFE)->mul;   /* gf mul  */
   mod_sqr  sqr = GFP_METHOD(pGFE)->sqr;   /* gf sqr  */

   BNU_CHUNK_T* mont1 = GFP_MNT_R(pGFE);

   /* coordinates of projective P point */
   const BNU_CHUNK_T* px = pPdata;              /* x1 */
   const BNU_CHUNK_T* py = pPdata+elemLen;      /* y1 */
   const BNU_CHUNK_T* pz = pPdata+2*elemLen;    /* z1 */

   /* coordinates of affine A point, az==mont(1) */
   const BNU_CHUNK_T* ax = pAdata;              /* x2 */
   const BNU_CHUNK_T* ay = pAdata+elemLen;      /* y2 */

   int inftyP = GFP_IS_ZERO(px, elemLen) && GFP_IS_ZERO(py, elemLen);
   int inftyA = GFP_IS_ZERO(ax, elemLen) && GFP_IS_ZERO(ay, elemLen);

   /* get temporary from top of EC point pool */
   BNU_CHUNK_T* U2 = pEC->pPool;
   BNU_CHUNK_T* S2 = U2 + elemLen;
   BNU_CHUNK_T* H  = S2 + elemLen;
   BNU_CHUNK_T* R  = H  + elemLen;

   BNU_CHUNK_T* pRx = R  + elemLen; /* temporary result */
   BNU_CHUNK_T* pRy = pRx+ elemLen;
   BNU_CHUNK_T* pRz = pRy+ elemLen;

   sqr(R, pz, pGFE);             // R = Z1^2
   mul(S2, ay, pz, pGFE);        // S2 = Y2*Z1
   mul(U2, ax, R, pGFE);         // U2 = X2*Z1^2
   mul(S2, S2, R, pGFE);         // S2 = Y2*Z1^3

   sub(H, U2, px, pGFE);         // H = U2-X1
   sub(R, S2, py, pGFE);         // R = S2-Y1

   mul(pRz, H, pz, pGFE);        // Z3 = H*Z1

   sqr(U2, H, pGFE);             // U2 = H^2
   sqr(S2, R, pGFE);             // S2 = R^2
   mul(H, H, U2, pGFE);          // H = H^3

   mul(U2, U2, px, pGFE);        // U2 = X1*H^2

   mul(pRy, H, py, pGFE);        // T = Y1*H^3

   mul2(pRx, U2, pGFE);          // X3 = 2*X1*H^2
   sub(pRx, S2, pRx, pGFE);      // X3 = R^2 - 2*X1*H^2
   sub(pRx, pRx, H, pGFE);       // X3 = R^2 - 2*X1*H^2 -H^3

   sub(U2, U2, pRx, pGFE);       // U2 = X1*H^2 - X3
   mul(U2, U2, R, pGFE);         // U2 = R*(X1*H^2 - X3)
   sub(pRy, U2, pRy, pGFE);      // Y3 = -Y1*H^3 + R*(X1*H^2 - X3)

   cpMaskMove(pRx, ax, elemLen, inftyP);
   cpMaskMove(pRy, ay, elemLen, inftyP);
   cpMaskMove(pRz, mont1, elemLen, inftyP);
   cpMaskMove(pRz, ax, elemLen, inftyP&inftyA);

   cpMaskMove(pRx, px, elemLen*3, inftyA);

   cpGFpElementCopy(pRdata, pRx, 3*elemLen);
}
#endif

IppsGFpECPoint* gfec_AddPoint(IppsGFpECPoint* pR,
                        const IppsGFpECPoint* pP, const IppsGFpECPoint* pQ,
                        IppsGFpECState* pEC)
{
   gfec_point_add(ECP_POINT_X(pR), ECP_POINT_X(pP), ECP_POINT_X(pQ), pEC);
   ECP_POINT_FLAGS(pR) = gfec_IsPointAtInfinity(pR)? 0 : ECP_FINITE_POINT;
   return pR;
}


/* sscm version */
static void setupTable(BNU_CHUNK_T* pTbl,
                 const BNU_CHUNK_T* pPdata,
                       IppsGFpECState* pEC)
{
   int pointLen = ECP_POINTLEN(pEC);
   //int pointLen32 = pointLen*sizeof(BNU_CHUNK_T)/sizeof(ipp32u);

   const int npoints = 3;
   BNU_CHUNK_T* A = cpEcGFpGetPool(npoints, pEC);
   BNU_CHUNK_T* B = A+pointLen;
   BNU_CHUNK_T* C = B+pointLen;

   // Table[0]
   // Table[0] is implicitly (0,0,0) {point at infinity}, therefore no need to store it
   // All other values are actually stored with an offset of -1

   // Table[1] ( =[1]p )
   //cpScatter32((Ipp32u*)pTbl, 16, 0, (Ipp32u*)pPdata, pointLen32);
   gsScramblePut(pTbl, (1-1), pPdata, pointLen, (5-1));

   // Table[2] ( =[2]p )
   gfec_point_double(A, pPdata, pEC);
   //cpScatter32((Ipp32u*)pTbl, 16, 1, (Ipp32u*)A, pointLen32);
   gsScramblePut(pTbl, (2-1), A, pointLen, (5-1));

   // Table[3] ( =[3]p )
   gfec_point_add(B, A, pPdata, pEC);
   //cpScatter32((Ipp32u*)pTbl, 16, 2, (Ipp32u*)B, pointLen32);
   gsScramblePut(pTbl, (3-1), B, pointLen, (5-1));

   // Table[4] ( =[4]p )
   gfec_point_double(A, A, pEC);
   //cpScatter32((Ipp32u*)pTbl, 16, 3, (Ipp32u*)A, pointLen32);
   gsScramblePut(pTbl, (4-1), A, pointLen, (5-1));

   // Table[5] ( =[5]p )
   gfec_point_add(C, A, pPdata, pEC);
   //cpScatter32((Ipp32u*)pTbl, 16, 4, (Ipp32u*)C, pointLen32);
   gsScramblePut(pTbl, (5-1), C, pointLen, (5-1));

   // Table[10] ( =[10]p )
   gfec_point_double(C, C, pEC);
   //cpScatter32((Ipp32u*)pTbl, 16, 9, (Ipp32u*)C, pointLen32);
   gsScramblePut(pTbl, (10-1), C, pointLen, (5-1));

   // Table[11] ( =[11]p )
   gfec_point_add(C, C, pPdata, pEC);
   //cpScatter32((Ipp32u*)pTbl, 16, 10, (Ipp32u*)C, pointLen32);
   gsScramblePut(pTbl, (11-1), C, pointLen, (5-1));

   // Table[6] ( =[6]p )
   gfec_point_double(B, B, pEC);
   //cpScatter32((Ipp32u*)pTbl, 16, 5, (Ipp32u*)B, pointLen32);
   gsScramblePut(pTbl, (6-1), B, pointLen, (5-1));

   // Table[7] ( =[7]p )
   gfec_point_add(C, B, pPdata, pEC);
   //cpScatter32((Ipp32u*)pTbl, 16, 6, (Ipp32u*)C, pointLen32);
   gsScramblePut(pTbl, (7-1), C, pointLen, (5-1));

   // Table[14] ( =[14]p )
   gfec_point_double(C, C, pEC);
   //cpScatter32((Ipp32u*)pTbl, 16, 13, (Ipp32u*)C, pointLen32);
   gsScramblePut(pTbl, (14-1), C, pointLen, (5-1));

   // Table[15] ( =[15]p )
   gfec_point_add(C, C, pPdata, pEC);
   //cpScatter32((Ipp32u*)pTbl, 16, 14, (Ipp32u*)C, pointLen32);
   gsScramblePut(pTbl, (15-1), C, pointLen, (5-1));

   // Table[12] ( =[12]p )
   gfec_point_double(B, B, pEC);
   //cpScatter32((Ipp32u*)pTbl, 16, 11, (Ipp32u*)B, pointLen32);
   gsScramblePut(pTbl, (12-1), B, pointLen, (5-1));

   // Table[13] ( =[13]p )
   gfec_point_add(B, B, pPdata, pEC);
   //cpScatter32((Ipp32u*)pTbl, 16, 12, (Ipp32u*)B, pointLen32);
   gsScramblePut(pTbl, (13-1), B, pointLen, (5-1));

   // Table[8] ( =[8]p )
   gfec_point_double(A, A, pEC);
   //cpScatter32((Ipp32u*)pTbl, 16, 7, (Ipp32u*)A, pointLen32);
   gsScramblePut(pTbl, (8-1), A, pointLen, (5-1));

   // Table[9] ( =[9]p )
   gfec_point_add(B, A, pPdata, pEC);
   //cpScatter32((Ipp32u*)pTbl, 16, 8, (Ipp32u*)B, pointLen32);
   gsScramblePut(pTbl, (9-1), B, pointLen, (5-1));

   // Table[16] ( =[16]p )
   gfec_point_double(A, A, pEC);
   //cpScatter32((Ipp32u*)pTbl, 16, 15, (Ipp32u*)A, pointLen32);
   gsScramblePut(pTbl, (16-1), A, pointLen, (5-1));

   cpEcGFpReleasePool(npoints, pEC);
}


static void gfec_point_mul(BNU_CHUNK_T* pRdata,
                     const BNU_CHUNK_T* pPdata,
                     const Ipp8u* pScalar8, int scalarBitSize,
                           IppsGFpECState* pEC, Ipp8u* pScratchBuffer)
{
   int pointLen = ECP_POINTLEN(pEC);
   //int pointLen32 = pointLen*sizeof(BNU_CHUNK_T)/sizeof(Ipp32u);

   /* optimal size of window */
   const int window_size = 5;
   /* number of table entries */
   //const int tableLen = 1<<(window_size-1);

   /* aligned pre-computed table */
   BNU_CHUNK_T* pTable = (BNU_CHUNK_T*)IPP_ALIGNED_PTR(pScratchBuffer, CACHE_LINE_SIZE);

   if (!pScratchBuffer)
      return;

   setupTable(pTable, pPdata, pEC);

   {
      IppsGFpState* pGF = ECP_GFP(pEC);
      gsModEngine* pGFE = GFP_PMA(pGF);
      int elemLen = GFP_FELEN(pGFE);

      mod_neg negF = GFP_METHOD(pGFE)->neg;

      BNU_CHUNK_T* pHy = cpGFpGetPool(1, pGFE);

      BNU_CHUNK_T* pTdata = cpEcGFpGetPool(1, pEC); /* points from the pool */
      BNU_CHUNK_T* pHdata = cpEcGFpGetPool(1, pEC);

      int wvalue;
      Ipp8u digit, sign;
      int mask = (1<<(window_size+1)) -1;
      int bit = scalarBitSize-(scalarBitSize%window_size);

      /* first window */
      if(bit) {
         wvalue = *((Ipp16u*)&pScalar8[(bit-1)/8]);
         wvalue = (wvalue>> ((bit-1)%8)) & mask;
      }
      else
         wvalue = 0;
      booth_recode(&sign, &digit, (Ipp8u)wvalue, window_size);
      //cpGather32((Ipp32u*)pTdata, pointLen32, (Ipp32u*)pTable, tableLen, digit);
      gsScrambleGet_sscm(pTdata, pointLen, pTable, digit-1, 5-1);

      for(bit-=window_size; bit>=window_size; bit-=window_size) {
         gfec_point_double(pTdata, pTdata, pEC); //it's better to have separate calls
         gfec_point_double(pTdata, pTdata, pEC); // instead of gfec_point_double_k()
         gfec_point_double(pTdata, pTdata, pEC);
         gfec_point_double(pTdata, pTdata, pEC);
         gfec_point_double(pTdata, pTdata, pEC);

         wvalue = *((Ipp16u*)&pScalar8[(bit-1)/8]);
         wvalue = (wvalue>> ((bit-1)%8)) & mask;
         booth_recode(&sign, &digit, (Ipp8u)wvalue, window_size);
         //cpGather32((Ipp32u*)pHdata, pointLen32, (Ipp32u*)pTable, tableLen, digit);
         gsScrambleGet_sscm(pHdata, pointLen, pTable, digit-1, 5-1);

         negF(pHy, pHdata+elemLen, pGFE);
         cpMaskMove(pHdata+elemLen, pHy, elemLen, sign);
         gfec_point_add(pTdata, pTdata, pHdata, pEC);
      }

      /* last window */
      gfec_point_double(pTdata, pTdata, pEC);
      gfec_point_double(pTdata, pTdata, pEC);
      gfec_point_double(pTdata, pTdata, pEC);
      gfec_point_double(pTdata, pTdata, pEC);
      gfec_point_double(pTdata, pTdata, pEC);

      wvalue = *((Ipp16u*)&pScalar8[0]);
      wvalue = (wvalue << 1) & mask;
      booth_recode(&sign, &digit, (Ipp8u)wvalue, window_size);
      //cpGather32((Ipp32u*)pHdata, pointLen32, (Ipp32u*)pTable, tableLen, digit);
      gsScrambleGet_sscm(pHdata, pointLen, pTable, digit-1, 5-1);

      negF(pHy, pHdata+elemLen, pGFE);
      cpMaskMove(pHdata+elemLen, pHy, elemLen, sign);
      gfec_point_add(pTdata, pTdata, pHdata, pEC);

      cpGFpElementCopy(pRdata, pTdata, pointLen);

      cpEcGFpReleasePool(2, pEC);
      cpGFpReleasePool(1, pGFE);
   }
}

static void gfec_base_point_mul(BNU_CHUNK_T* pRdata, const Ipp8u* pScalar8, int scalarBitSize, IppsGFpECState* pEC)
{
   /* size of window, get function and pre-computed table */
   int window_size = ECP_PREMULBP(pEC)->w;
   selectAP select_affine_point = ECP_PREMULBP(pEC)->select_affine_point;
   const BNU_CHUNK_T* pTbl = ECP_PREMULBP(pEC)->pTbl;

   IppsGFpState* pGF = ECP_GFP(pEC);
   gsModEngine* pGFE = GFP_PMA(pGF);
   int elmLen = GFP_FELEN(pGFE);

   mod_neg negF = GFP_METHOD(pGFE)->neg;

   BNU_CHUNK_T* mont1 = GFP_MNT_R(pGFE);

   /* number of points per table slot */
   int tslot_point = 1<<(window_size-1);
   int tslot_size = tslot_point * (elmLen*2);

   BNU_CHUNK_T* negtmp = cpGFpGetPool(1, pGFE);  /* temporary element */
   BNU_CHUNK_T* pointT = cpEcGFpGetPool(1, pEC); /* temporary point */

   Ipp8u digit, sign;
   int mask = (1<<(window_size+1)) -1;
   int bit = 0;

   /* processing of window[0] */
   int wvalue = *((Ipp16u*)&pScalar8[0]);
   wvalue = (wvalue << 1) & mask;

   booth_recode(&sign, &digit, (Ipp8u)wvalue, window_size);
   select_affine_point(pRdata, pTbl, digit);

   negF(negtmp, pRdata+elmLen, pGFE);
   cpMaskMove(pRdata+elmLen, negtmp, elmLen, sign);
   cpGFpElementCopy(pRdata+elmLen*2, mont1, elmLen);
   cpGFpElementCopy(pointT+elmLen*2, mont1, elmLen);

   /* processing of other windows.. [1],[2],... */
   for(bit+=window_size, pTbl+=tslot_size; bit<=scalarBitSize; bit+=window_size, pTbl+=tslot_size) {
      wvalue = *((Ipp16u*)&pScalar8[(bit-1)/8]);
      wvalue = (wvalue>> ((bit-1)%8)) & mask;

      booth_recode(&sign, &digit, (Ipp8u)wvalue, window_size);
      select_affine_point(pointT, pTbl, digit);

      negF(negtmp, pointT+elmLen, pGFE);
      cpMaskMove(pointT+elmLen, negtmp, elmLen, sign);

      gfec_affine_point_add(pRdata, pRdata, pointT, pEC);
   }

   cpEcGFpReleasePool(1, pEC);
   cpGFpReleasePool(1, pGFE);
}

static void gfec_point_prod(BNU_CHUNK_T* pointR,
                     const BNU_CHUNK_T* pointA, const Ipp8u* scalarA,
                     const BNU_CHUNK_T* pointB, const Ipp8u* scalarB,
                     int scalarBitSize,
                     IppsGFpECState* pEC, Ipp8u* pScratchBuffer)
{
   int pointLen = ECP_POINTLEN(pEC);
   //int pointLen32 = pointLen*sizeof(BNU_CHUNK_T)/sizeof(Ipp32u);

   /* optimal size of window */
   const int window_size = 5;
   /* number of table entries */
   const int tableLen = 1<<(window_size-1);

   /* aligned pre-computed tables */
   BNU_CHUNK_T* pTableA = (BNU_CHUNK_T*)IPP_ALIGNED_PTR(pScratchBuffer, CACHE_LINE_SIZE);
   BNU_CHUNK_T* pTableB = pTableA+pointLen*tableLen;

   if (!pScratchBuffer)
      return;

   setupTable(pTableA, pointA, pEC);
   setupTable(pTableB, pointB, pEC);

   {
      IppsGFpState* pGF = ECP_GFP(pEC);
      gsModEngine* pGFE = GFP_PMA(pGF);
      int elemLen = GFP_FELEN(pGFE);

      mod_neg negF = GFP_METHOD(pGFE)->neg;

      BNU_CHUNK_T* pHy = cpGFpGetPool(1, pGFE);

      BNU_CHUNK_T* pTdata = cpEcGFpGetPool(1, pEC); /* points from the pool */
      BNU_CHUNK_T* pHdata = cpEcGFpGetPool(1, pEC);

      int wvalue;
      Ipp8u digit, sign;
      int mask = (1<<(window_size+1)) -1;
      int bit = scalarBitSize-(scalarBitSize%window_size);

      /* first window */
      if(bit) {
         wvalue = *((Ipp16u*)&scalarA[(bit-1)/8]);
         wvalue = (wvalue>> ((bit-1)%8)) & mask;
      }
      else
         wvalue = 0;
      booth_recode(&sign, &digit, (Ipp8u)wvalue, window_size);
      //cpGather32((Ipp32u*)pTdata, pointLen32, (Ipp32u*)pTableA, tableLen, digit);
      gsScrambleGet_sscm(pTdata, pointLen, pTableA, digit-1, 5-1);

      if(bit) {
         wvalue = *((Ipp16u*)&scalarB[(bit-1)/8]);
         wvalue = (wvalue>> ((bit-1)%8)) & mask;
      }
      else
         wvalue = 0;
      booth_recode(&sign, &digit, (Ipp8u)wvalue, window_size);
      //cpGather32((Ipp32u*)pHdata, pointLen32, (Ipp32u*)pTableB, tableLen, digit);
      gsScrambleGet_sscm(pHdata, pointLen, pTableB, digit-1, 5-1);

      //negF(pHy, pHdata+elemLen, pGFE);
      //cpMaskMove(pHdata+elemLen, pHy, elemLen, sign);
      gfec_point_add(pTdata, pTdata, pHdata, pEC);

      for(bit-=window_size; bit>=window_size; bit-=window_size) {
         gfec_point_double(pTdata, pTdata, pEC);
         gfec_point_double(pTdata, pTdata, pEC);
         gfec_point_double(pTdata, pTdata, pEC);
         gfec_point_double(pTdata, pTdata, pEC);
         gfec_point_double(pTdata, pTdata, pEC);

         wvalue = *((Ipp16u*)&scalarA[(bit-1)/8]);
         wvalue = (wvalue>> ((bit-1)%8)) & mask;
         booth_recode(&sign, &digit, (Ipp8u)wvalue, window_size);
         //cpGather32((Ipp32u*)pHdata, pointLen32, (Ipp32u*)pTableA, tableLen, digit);
         gsScrambleGet_sscm(pHdata, pointLen, pTableA, digit-1, 5-1);

         negF(pHy, pHdata+elemLen, pGFE);
         cpMaskMove(pHdata+elemLen, pHy, elemLen, sign);
         gfec_point_add(pTdata, pTdata, pHdata, pEC);

         wvalue = *((Ipp16u*)&scalarB[(bit-1)/8]);
         wvalue = (wvalue>> ((bit-1)%8)) & mask;
         booth_recode(&sign, &digit, (Ipp8u)wvalue, window_size);
         //cpGather32((Ipp32u*)pHdata, pointLen32, (Ipp32u*)pTableB, tableLen, digit);
         gsScrambleGet_sscm(pHdata, pointLen, pTableB, digit-1, 5-1);

         negF(pHy, pHdata+elemLen, pGFE);
         cpMaskMove(pHdata+elemLen, pHy, elemLen, sign);
         gfec_point_add(pTdata, pTdata, pHdata, pEC);
      }
      /* last window */
      gfec_point_double(pTdata, pTdata, pEC);
      gfec_point_double(pTdata, pTdata, pEC);
      gfec_point_double(pTdata, pTdata, pEC);
      gfec_point_double(pTdata, pTdata, pEC);
      gfec_point_double(pTdata, pTdata, pEC);

      wvalue = *((Ipp16u*)&scalarA[0]);
      wvalue = (wvalue << 1) & mask;
      booth_recode(&sign, &digit, (Ipp8u)wvalue, window_size);
      //cpGather32((Ipp32u*)pHdata, pointLen32, (Ipp32u*)pTableA, tableLen, digit);
      gsScrambleGet_sscm(pHdata, pointLen, pTableA, digit-1, 5-1);

      negF(pHy, pHdata+elemLen, pGFE);
      cpMaskMove(pHdata+elemLen, pHy, elemLen, sign);
      gfec_point_add(pTdata, pTdata, pHdata, pEC);

      wvalue = *((Ipp16u*)&scalarB[0]);
      wvalue = (wvalue << 1) & mask;
      booth_recode(&sign, &digit, (Ipp8u)wvalue, window_size);
      //cpGather32((Ipp32u*)pHdata, pointLen32, (Ipp32u*)pTableB, tableLen, digit);
      gsScrambleGet_sscm(pHdata, pointLen, pTableB, digit-1, 5-1);

      negF(pHy, pHdata+elemLen, pGFE);
      cpMaskMove(pHdata+elemLen, pHy, elemLen, sign);
      gfec_point_add(pTdata, pTdata, pHdata, pEC);

      cpGFpElementCopy(pointR, pTdata, pointLen);

      cpEcGFpReleasePool(2, pEC);
      cpGFpReleasePool(1, pGFE);
   }
}

/*
// select affine point
*/
#if (_IPP32E < _IPP32E_M7)
void p192r1_select_ap_w7(BNU_CHUNK_T* pVal, const BNU_CHUNK_T* pTbl, int idx)
{
   #define OPERAND_BITSIZE (192)
   #define LEN_P192        (BITS_BNU_CHUNK(OPERAND_BITSIZE))
   #define LEN_P192_APOINT (2*LEN_P192)

   const int tblLen = 64;
   int i;
   unsigned int n;

   /* clear output affine point */
   for(n=0; n<LEN_P192_APOINT; n++)
      pVal[n] = 0;

   /* select poiint */
   for(i=1; i<=tblLen; i++) {
      BNU_CHUNK_T mask = 0 - isZero(i-idx);
      for(n=0; n<LEN_P192_APOINT; n++)
         pVal[n] |= (pTbl[n] & mask);
      pTbl += LEN_P192_APOINT;
   }

   #undef OPERAND_BITSIZE
   #undef LEN_P192
   #undef LEN_P192_APOINT
}

void p224r1_select_ap_w7(BNU_CHUNK_T* pVal, const BNU_CHUNK_T* pTbl, int idx)
{
   #define OPERAND_BITSIZE (224)
   #define LEN_P224        (BITS_BNU_CHUNK(OPERAND_BITSIZE))
   #define LEN_P224_APOINT (2*LEN_P224)

   const int tblLen = 64;
   int i;
   unsigned int n;

   /* clear output affine point */
   for(n=0; n<LEN_P224_APOINT; n++)
      pVal[n] = 0;

   /* select poiint */
   for(i=1; i<=tblLen; i++) {
      BNU_CHUNK_T mask = 0 - isZero(i-idx);
      for(n=0; n<LEN_P224_APOINT; n++)
         pVal[n] |= (pTbl[n] & mask);
      pTbl += LEN_P224_APOINT;
   }

   #undef OPERAND_BITSIZE
   #undef LEN_P224
   #undef LEN_P224_APOINT
}

void p256r1_select_ap_w7(BNU_CHUNK_T* pVal, const BNU_CHUNK_T* pTbl, int idx)
{
   #define OPERAND_BITSIZE (256)
   #define LEN_P256        (BITS_BNU_CHUNK(OPERAND_BITSIZE))
   #define LEN_P256_APOINT (2*LEN_P256)

   const int tblLen = 64;
   int i;
   unsigned int n;

   /* clear output affine point */
   for(n=0; n<LEN_P256_APOINT; n++)
      pVal[n] = 0;

   /* select poiint */
   for(i=1; i<=tblLen; i++) {
      BNU_CHUNK_T mask = 0 - isZero(i-idx);
      for(n=0; n<LEN_P256_APOINT; n++)
         pVal[n] |= (pTbl[n] & mask);
      pTbl += LEN_P256_APOINT;
   }

   #undef OPERAND_BITSIZE
   #undef LEN_P256
   #undef LEN_P256_APOINT
}

void p384r1_select_ap_w5(BNU_CHUNK_T* pVal, const BNU_CHUNK_T* pTbl, int idx)
{
   #define OPERAND_BITSIZE (384)
   #define LEN_P384        (BITS_BNU_CHUNK(OPERAND_BITSIZE))
   #define LEN_P384_APOINT (2*LEN_P384)

   const int tblLen = 16;
   int i;
   unsigned int n;

   /* clear output affine point */
   for(n=0; n<LEN_P384_APOINT; n++)
      pVal[n] = 0;

   /* select poiint */
   for(i=1; i<=tblLen; i++) {
      BNU_CHUNK_T mask = 0 - isZero(i-idx);
      for(n=0; n<LEN_P384_APOINT; n++)
         pVal[n] |= (pTbl[n] & mask);
      pTbl += LEN_P384_APOINT;
   }

   #undef OPERAND_BITSIZE
   #undef LEN_P384
   #undef LEN_P384_APOINT
}

void p521r1_select_ap_w5(BNU_CHUNK_T* pVal, const BNU_CHUNK_T* pTbl, int idx)
{
   #define OPERAND_BITSIZE (521)
   #define LEN_P521        (BITS_BNU_CHUNK(OPERAND_BITSIZE))
   #define LEN_P521_APOINT (2*LEN_P521)

   const int tblLen = 16;
   int i;
   unsigned int n;

   /* clear output affine point */
   for(n=0; n<LEN_P521_APOINT; n++)
      pVal[n] = 0;

   /* select point */
   for(i=1; i<=tblLen; i++) {
      BNU_CHUNK_T mask = 0 - isZero(i-idx);
      for(n=0; n<LEN_P521_APOINT; n++)
         pVal[n] |= (pTbl[n] & mask);
      pTbl += LEN_P521_APOINT;
   }

   #undef OPERAND_BITSIZE
   #undef LEN_P521
   #undef P521_POINT_AFFINE
}
#endif

IppsGFpECPoint* gfec_MulPoint(IppsGFpECPoint* pR,
                        const IppsGFpECPoint* pP,
                        const BNU_CHUNK_T* pScalar, int scalarLen,
                        IppsGFpECState* pEC, Ipp8u* pScratchBuffer)
{
   FIX_BNU(pScalar, scalarLen);
   {
      gsModEngine* pGForder = ECP_MONT_R(pEC);

      BNU_CHUNK_T* pTmpScalar = cpGFpGetPool(1, pGForder); /* length of scalar does not exceed length of order */
      int orderBits = MOD_BITSIZE(pGForder);
      int orderLen  = MOD_LEN(pGForder);
      cpGFpElementCopyPadd(pTmpScalar,orderLen+1, pScalar,scalarLen);

      gfec_point_mul(ECP_POINT_X(pR), ECP_POINT_X(pP),
                  (Ipp8u*)pTmpScalar, orderBits,
                  pEC, pScratchBuffer);
      cpGFpReleasePool(1, pGForder);

      ECP_POINT_FLAGS(pR) = gfec_IsPointAtInfinity(pR)? 0 : ECP_FINITE_POINT;
      return pR;
   }
}

IppsGFpECPoint* gfec_MulBasePoint(IppsGFpECPoint* pR,
                            const BNU_CHUNK_T* pScalar, int scalarLen,
                            IppsGFpECState* pEC, Ipp8u* pScratchBuffer)
{
   FIX_BNU(pScalar, scalarLen);
   {
      gsModEngine* pGForder = ECP_MONT_R(pEC);

      BNU_CHUNK_T* pTmpScalar = cpGFpGetPool(1, pGForder); /* length of scalar does not exceed length of order */
      int orderBits = MOD_BITSIZE(pGForder);
      int orderLen  = MOD_LEN(pGForder);
      cpGFpElementCopyPadd(pTmpScalar,orderLen+1, pScalar,scalarLen);

      if(ECP_PREMULBP(pEC))
         gfec_base_point_mul(ECP_POINT_X(pR),
                             (Ipp8u*)pTmpScalar, orderBits,
                             pEC);
      else
         gfec_point_mul(ECP_POINT_X(pR), ECP_G(pEC),
                        (Ipp8u*)pTmpScalar, orderBits,
                        pEC, pScratchBuffer);
      cpGFpReleasePool(1, pGForder);

      ECP_POINT_FLAGS(pR) = gfec_IsPointAtInfinity(pR)? 0 : ECP_FINITE_POINT;
      return pR;
   }
}

IppsGFpECPoint* gfec_PointProduct(IppsGFpECPoint* pR,
                        const IppsGFpECPoint* pP, const BNU_CHUNK_T* pScalarP, int scalarPlen,
                        const IppsGFpECPoint* pQ, const BNU_CHUNK_T* pScalarQ, int scalarQlen,
                        IppsGFpECState* pEC, Ipp8u* pScratchBuffer)
{
   FIX_BNU(pScalarP, scalarPlen);
   FIX_BNU(pScalarQ, scalarQlen);
   {
      gsModEngine* pGForder = ECP_MONT_R(pEC);

      int orderBits = MOD_BITSIZE(pGForder);
      int orderLen  = MOD_LEN(pGForder);
      BNU_CHUNK_T* tmpScalarP = cpGFpGetPool(2, pGForder);
      BNU_CHUNK_T* tmpScalarQ = tmpScalarP+orderLen+1;
      cpGFpElementCopyPadd(tmpScalarP, orderLen+1, pScalarP,scalarPlen);
      cpGFpElementCopyPadd(tmpScalarQ, orderLen+1, pScalarQ,scalarQlen);

      gfec_point_prod(ECP_POINT_X(pR),
                      ECP_POINT_X(pP), (Ipp8u*)tmpScalarP,
                      ECP_POINT_X(pQ), (Ipp8u*)tmpScalarQ,
                      orderBits,
                      pEC, pScratchBuffer);
      cpGFpReleasePool(2, pGForder);

      ECP_POINT_FLAGS(pR) = gfec_IsPointAtInfinity(pR)? 0 : ECP_FINITE_POINT;
      return pR;
   }
}

IppsGFpECPoint* gfec_BasePointProduct(IppsGFpECPoint* pR,
                        const BNU_CHUNK_T* pScalarG, int scalarGlen,
                        const IppsGFpECPoint* pP, const BNU_CHUNK_T* pScalarP, int scalarPlen,
                        IppsGFpECState* pEC, Ipp8u* pScratchBuffer)
{
   FIX_BNU(pScalarG, scalarGlen);
   FIX_BNU(pScalarP, scalarPlen);

   {
      gsModEngine* pGForder = ECP_MONT_R(pEC);
      int orderBits = MOD_BITSIZE(pGForder);
      int orderLen  = MOD_LEN(pGForder);
      BNU_CHUNK_T* tmpScalarG = cpGFpGetPool(2, pGForder);
      BNU_CHUNK_T* tmpScalarP = tmpScalarG+orderLen+1;

      cpGFpElementCopyPadd(tmpScalarG, orderLen+1, pScalarG,scalarGlen);
      cpGFpElementCopyPadd(tmpScalarP, orderLen+1, pScalarP,scalarPlen);

      if(ECP_PREMULBP(pEC)) {
         BNU_CHUNK_T* productG = cpEcGFpGetPool(2, pEC);
         BNU_CHUNK_T* productP = productG+ECP_POINTLEN(pEC);

         gfec_base_point_mul(productG, (Ipp8u*)tmpScalarG, orderBits, pEC);
         gfec_point_mul(productP, ECP_POINT_X(pP), (Ipp8u*)tmpScalarP, orderBits, pEC, pScratchBuffer);
         gfec_point_add(ECP_POINT_X(pR), productG, productP, pEC);

         cpEcGFpReleasePool(2, pEC);
      }

      else {
         gfec_point_prod(ECP_POINT_X(pR),
                         ECP_G(pEC), (Ipp8u*)tmpScalarG,
                         ECP_POINT_X(pP), (Ipp8u*)tmpScalarP,
                         orderBits,
                         pEC, pScratchBuffer);
      }

      cpGFpReleasePool(2, pGForder);
   }

   ECP_POINT_FLAGS(pR) = gfec_IsPointAtInfinity(pR)? 0 : ECP_FINITE_POINT;
   return pR;
}
