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
//     Digesting message according to SHA256
// 
//  Contents:
//     ippsSHA256GetSize()
//     ippsSHA256Init()
//     ippsSHA256Pack()
//     ippsSHA256Unpack()
//     ippsSHA256Duplicate()
//     ippsSHA256Update()
//     ippsSHA256GetTag()
//     ippsSHA256Final()
//     ippsSHA256MessageDigest()
// 
// 
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcphash.h"
#include "pcphash_rmf.h"
#include "pcptool.h"

/* SHA-256, SHA-224 constants */
static const Ipp32u sha256_iv[] = {
   0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
   0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};
static const Ipp32u sha224_iv[] = {
   0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
   0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4};

static __ALIGN16 const Ipp32u sha256_cnt[] = {
   0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
   0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
   0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
   0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
   0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
   0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
   0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
   0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
   0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
   0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
   0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
   0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
   0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
   0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
   0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
   0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};


/* setup init hash value */
__INLINE void hashInit(Ipp32u* pHash, const Ipp32u* iv)
{
   pHash[0] = iv[0];
   pHash[1] = iv[1];
   pHash[2] = iv[2];
   pHash[3] = iv[3];
   pHash[4] = iv[4];
   pHash[5] = iv[5];
   pHash[6] = iv[6];
   pHash[7] = iv[7];
}
static void sha256_hashInit(void* pHash)
{
   hashInit((Ipp32u*)pHash, sha256_iv);
}
static void sha224_hashInit(void* pHash)
{
   hashInit((Ipp32u*)pHash, sha224_iv);
}

static void sha256_hashUpdate(void* pHash, const Ipp8u* pMsg, int msgLen)
{
   UpdateSHA256(pHash, pMsg, msgLen, sha256_cnt);
}
#if (_SHA_NI_ENABLING_==_FEATURE_TICKTOCK_ || _SHA_NI_ENABLING_==_FEATURE_ON_)
static void sha256_ni_hashUpdate(void* pHash, const Ipp8u* pMsg, int msgLen)
{
   UpdateSHA256ni(pHash, pMsg, msgLen, sha256_cnt);
}
#endif

/* convert hash into big endian */
static void sha256_hashOctString(Ipp8u* pMD, void* pHashVal)
{
   /* convert hash into big endian */
   ((Ipp32u*)pMD)[0] = ENDIANNESS32(((Ipp32u*)pHashVal)[0]);
   ((Ipp32u*)pMD)[1] = ENDIANNESS32(((Ipp32u*)pHashVal)[1]);
   ((Ipp32u*)pMD)[2] = ENDIANNESS32(((Ipp32u*)pHashVal)[2]);
   ((Ipp32u*)pMD)[3] = ENDIANNESS32(((Ipp32u*)pHashVal)[3]);
   ((Ipp32u*)pMD)[4] = ENDIANNESS32(((Ipp32u*)pHashVal)[4]);
   ((Ipp32u*)pMD)[5] = ENDIANNESS32(((Ipp32u*)pHashVal)[5]);
   ((Ipp32u*)pMD)[6] = ENDIANNESS32(((Ipp32u*)pHashVal)[6]);
   ((Ipp32u*)pMD)[7] = ENDIANNESS32(((Ipp32u*)pHashVal)[7]);
}
static void sha224_hashOctString(Ipp8u* pMD, void* pHashVal)
{
   /* convert hash into big endian */
   ((Ipp32u*)pMD)[0] = ENDIANNESS32(((Ipp32u*)pHashVal)[0]);
   ((Ipp32u*)pMD)[1] = ENDIANNESS32(((Ipp32u*)pHashVal)[1]);
   ((Ipp32u*)pMD)[2] = ENDIANNESS32(((Ipp32u*)pHashVal)[2]);
   ((Ipp32u*)pMD)[3] = ENDIANNESS32(((Ipp32u*)pHashVal)[3]);
   ((Ipp32u*)pMD)[4] = ENDIANNESS32(((Ipp32u*)pHashVal)[4]);
   ((Ipp32u*)pMD)[5] = ENDIANNESS32(((Ipp32u*)pHashVal)[5]);
   ((Ipp32u*)pMD)[6] = ENDIANNESS32(((Ipp32u*)pHashVal)[6]);
}

static void sha256_msgRep(Ipp8u* pDst, Ipp64u lenLo, Ipp64u lenHi)
{
   UNREFERENCED_PARAMETER(lenHi);
   lenLo = ENDIANNESS64(lenLo<<3);
   ((Ipp64u*)(pDst))[0] = lenLo;
}


/*
// SHA256 init context
*/
static IppStatus GetSizeSHA256(int* pSize)
{
   IPP_BAD_PTR1_RET(pSize);
   *pSize = sizeof(IppsSHA256State) +(SHA256_ALIGNMENT-1);
   return ippStsNoErr;
}

static IppStatus InitSHA256(IppsSHA256State* pState, const DigestSHA256 IV)
{
   /* test state pointer */
   IPP_BAD_PTR1_RET(pState);
   pState = (IppsSHA256State*)( IPP_ALIGNED_PTR(pState, SHA256_ALIGNMENT) );

   HASH_CTX_ID(pState) = idCtxSHA256;
   HASH_LENLO(pState) = 0;
   HAHS_BUFFIDX(pState) = 0;

   /* setup initial digest */
   HASH_VALUE(pState)[0] = IV[0];
   HASH_VALUE(pState)[1] = IV[1];
   HASH_VALUE(pState)[2] = IV[2];
   HASH_VALUE(pState)[3] = IV[3];
   HASH_VALUE(pState)[4] = IV[4];
   HASH_VALUE(pState)[5] = IV[5];
   HASH_VALUE(pState)[6] = IV[6];
   HASH_VALUE(pState)[7] = IV[7];

   return ippStsNoErr;
}

/*F*
//    Name: ippsSHA256GetSize
//          ippsSHA224GetSize
//
// Purpose: Returns size (bytes) of IppsSHA256State state.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize       pointer to state size
//
*F*/
IPPFUN(IppStatus, ippsSHA256GetSize,(int* pSize))
{
   return GetSizeSHA256(pSize);
}
IPPFUN(IppStatus, ippsSHA224GetSize,(int* pSize))
{
   return GetSizeSHA256(pSize);
}


/*F*
//    Name: ippsSHA256Init
//          ippsSHA224Init
//
// Purpose: Init SHA256
//
// Returns:                Reason:
//    ippStsNullPtrErr        pState == NULL
//    ippStsNoErr             no errors
//
// Parameters:
//    pState      pointer to the SHA512 state
//
*F*/
IPPFUN(IppStatus, ippsSHA256Init,(IppsSHA256State* pState))
{
   return InitSHA256(pState, sha256_iv);
}
IPPFUN(IppStatus, ippsSHA224Init,(IppsSHA224State* pState))
{
   return InitSHA256(pState, sha224_iv);
}


/*F*
//    Name: ippsSHA256Pack
//          ippsSHA224Pack
//
// Purpose: Copy initialized context to the buffer.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//                            pBuffer == NULL
//    ippStsNoErr             no errors
//
// Parameters:
//    pCtx        pointer to the hash state
//    pBuffer     pointer to the destination buffer
//
*F*/
IPPFUN(IppStatus, ippsSHA256Pack,(const IppsSHA256State* pCtx, Ipp8u* pBuffer))
{
   /* test pointers */
   IPP_BAD_PTR2_RET(pCtx, pBuffer);
   pCtx = (IppsSHA256State*)( IPP_ALIGNED_PTR(pCtx, SHA256_ALIGNMENT) );
   IPP_BADARG_RET(idCtxSHA256 !=HASH_CTX_ID(pCtx), ippStsContextMatchErr);

   CopyBlock(pCtx, pBuffer, sizeof(IppsSHA256State));
   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsSHA224Pack,(const IppsSHA224State* pCtx, Ipp8u* pBuffer))
{
   return ippsSHA256Pack(pCtx, pBuffer);
}


/*F*
//    Name: ippsSHA256Unpack
//          ippsSHA224Unpack
//
// Purpose: Unpack buffer content into the initialized context.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//                            pBuffer == NULL
//    ippStsNoErr             no errors
//
// Parameters:
//    pBuffer     pointer to the input buffer
//    pCtx        pointer hash state
//
*F*/
IPPFUN(IppStatus, ippsSHA256Unpack,(const Ipp8u* pBuffer, IppsSHA256State* pCtx))
{
   /* test pointers */
   IPP_BAD_PTR2_RET(pCtx, pBuffer);
   pCtx = (IppsSHA256State*)( IPP_ALIGNED_PTR(pCtx, SHA256_ALIGNMENT) );

   CopyBlock(pBuffer, pCtx, sizeof(IppsSHA256State));
   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsSHA224Unpack,(const Ipp8u* pBuffer, IppsSHA224State* pCtx))
{
   return ippsSHA256Unpack(pBuffer, pCtx);
}


/*F*
//    Name: ippsSHA256Duplicate
//          ippsSHA224Duplicate
//
// Purpose: Clone SHA256 state.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSrcState == NULL
//                            pDstState == NULL
//    ippStsContextMatchErr   pSrcState->idCtx != idCtxSHA256
//                            pDstState->idCtx != idCtxSHA256
//    ippStsNoErr             no errors
//
// Parameters:
//    pSrcState   pointer to the source SHA256 state
//    pDstState   pointer to the target SHA256 state
//
// Note:
//    pDstState may to be uninitialized by ippsSHA256Init()
//
*F*/
IPPFUN(IppStatus, ippsSHA256Duplicate,(const IppsSHA256State* pSrcState, IppsSHA256State* pDstState))
{
   /* test state pointers */
   IPP_BAD_PTR2_RET(pSrcState, pDstState);
   pSrcState = (IppsSHA256State*)( IPP_ALIGNED_PTR(pSrcState, SHA256_ALIGNMENT) );
   pDstState = (IppsSHA256State*)( IPP_ALIGNED_PTR(pDstState, SHA256_ALIGNMENT) );
   /* test states ID */
   IPP_BADARG_RET(idCtxSHA256 !=HASH_CTX_ID(pSrcState), ippStsContextMatchErr);

   /* copy state */
   CopyBlock(pSrcState, pDstState, sizeof(IppsSHA256State));

   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsSHA224Duplicate,(const IppsSHA224State* pSrcState, IppsSHA224State* pDstState))
{
   return ippsSHA256Duplicate(pSrcState, pDstState);
}


/*F*
//    Name: ippsSHA256Update
//          ippsSHA224Update
//
// Purpose: Updates intermadiate digest based on input stream.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSrc == NULL
//                            pState == NULL
//    ippStsContextMatchErr   pState->idCtx != idCtxSHA256
//    ippStsLengthErr         len <0
//    ippStsNoErr             no errors
//
// Parameters:
//    pSrc        pointer to the input stream
//    len         input stream length
//    pState      pointer to the SHA256 state
//
*F*/
IPPFUN(IppStatus, ippsSHA256Update,(const Ipp8u* pSrc, int len, IppsSHA256State* pState))
{
   /* test state pointer and ID */
   IPP_BAD_PTR1_RET(pState);
   pState = (IppsSHA256State*)( IPP_ALIGNED_PTR(pState, SHA256_ALIGNMENT) );
   IPP_BADARG_RET(idCtxSHA256 !=HASH_CTX_ID(pState), ippStsContextMatchErr);

   /* test input length */
   IPP_BADARG_RET((len<0), ippStsLengthErr);
   /* test source pointer */
   IPP_BADARG_RET((len && !pSrc), ippStsNullPtrErr);

   /*
   // handle non empty message
   */
   if(len) {
      /* select processing function */
      #if (_SHA_NI_ENABLING_==_FEATURE_ON_)
      cpHashProc updateFunc = UpdateSHA256ni;
      #elif (_SHA_NI_ENABLING_==_FEATURE_TICKTOCK_)
      cpHashProc updateFunc = IsFeatureEnabled(SHA_NI_ENABLED)? UpdateSHA256ni : UpdateSHA256;
      #else
      cpHashProc updateFunc = UpdateSHA256;
      #endif

      int procLen;

      int idx = HAHS_BUFFIDX(pState);
      Ipp8u* pBuffer = HASH_BUFF(pState);
      Ipp64u lenLo = HASH_LENLO(pState) +len;

      /* if non empty internal buffer filling */
      if(idx) {
         /* copy from input stream to the internal buffer as match as possible */
         procLen = IPP_MIN(len, (MBS_SHA256-idx));
         CopyBlock(pSrc, pBuffer+idx, procLen);
         
         /* update message pointer and length */
         pSrc += procLen;
         len  -= procLen;
         idx  += procLen;

         /* update digest if buffer full */
         if( MBS_SHA256 == idx) {
            updateFunc(HASH_VALUE(pState), pBuffer, MBS_SHA256, sha256_cnt);
            idx = 0;
         }
      }

      /* main message part processing */
      procLen = len & ~(MBS_SHA256-1);
      if(procLen) {
         updateFunc(HASH_VALUE(pState), pSrc, procLen, sha256_cnt);
         pSrc += procLen;
         len  -= procLen;
      }

      /* store rest of message into the internal buffer */
      if(len) {
         CopyBlock(pSrc, pBuffer, len);
         idx += len;
      }

      /* update length of processed message */
      HASH_LENLO(pState) = lenLo;
      HAHS_BUFFIDX(pState) = idx;
   }

   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsSHA224Update,(const Ipp8u* pSrc, int len, IppsSHA224State* pState))
{
   return ippsSHA256Update(pSrc, len, pState);
}


static void cpFinalizeSHA256(DigestSHA256 pHash, const Ipp8u* inpBuffer, int inpLen, Ipp64u processedMsgLen)
{
   /* select processing  function */
   #if (_SHA_NI_ENABLING_==_FEATURE_ON_)
   cpHashProc updateFunc = UpdateSHA256ni;
   #elif (_SHA_NI_ENABLING_==_FEATURE_TICKTOCK_)
   cpHashProc updateFunc = IsFeatureEnabled(SHA_NI_ENABLED)? UpdateSHA256ni : UpdateSHA256;
   #else
   cpHashProc updateFunc = UpdateSHA256;
   #endif

   /* local buffer and it length */
   Ipp8u buffer[MBS_SHA256*2];
   int bufferLen = inpLen < (MBS_SHA256-(int)MLR_SHA256)? MBS_SHA256 : MBS_SHA256*2; 

   /* copy rest of message into internal buffer */
   CopyBlock(inpBuffer, buffer, inpLen);

   /* padd message */
   buffer[inpLen++] = 0x80;
   PaddBlock(0, buffer+inpLen, bufferLen-inpLen-MLR_SHA256);

   /* put processed message length in bits */
   processedMsgLen = ENDIANNESS64(processedMsgLen<<3);
   ((Ipp64u*)(buffer+bufferLen))[-1] = processedMsgLen;

   /* copmplete hash computation */
   updateFunc(pHash, buffer, bufferLen, sha256_cnt);
}

/*F*
//    Name: ippsSHA256Final
//          ippsSHA224Final
//
// Purpose: Stop message digesting and return digest.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pDigest == NULL
//                            pState == NULL
//    ippStsContextMatchErr   pState->idCtx != idCtxSHA256
//    ippStsNoErr             no errors
//
// Parameters:
//    pMD         address of the output digest
//    pState      pointer to the SHA256 state
//
*F*/
IPPFUN(IppStatus, ippsSHA256Final,(Ipp8u* pMD, IppsSHA256State* pState))
{
   /* test state pointer and ID */
   IPP_BAD_PTR1_RET(pState);
   pState = (IppsSHA256State*)( IPP_ALIGNED_PTR(pState, SHA256_ALIGNMENT) );
   IPP_BADARG_RET(idCtxSHA256 !=HASH_CTX_ID(pState), ippStsContextMatchErr);

   /* test digest pointer */
   IPP_BAD_PTR1_RET(pMD);

   cpFinalizeSHA256(HASH_VALUE(pState), HASH_BUFF(pState), HAHS_BUFFIDX(pState), HASH_LENLO(pState));
   /* convert hash into big endian */
   ((Ipp32u*)pMD)[0] = ENDIANNESS32(HASH_VALUE(pState)[0]);
   ((Ipp32u*)pMD)[1] = ENDIANNESS32(HASH_VALUE(pState)[1]);
   ((Ipp32u*)pMD)[2] = ENDIANNESS32(HASH_VALUE(pState)[2]);
   ((Ipp32u*)pMD)[3] = ENDIANNESS32(HASH_VALUE(pState)[3]);
   ((Ipp32u*)pMD)[4] = ENDIANNESS32(HASH_VALUE(pState)[4]);
   ((Ipp32u*)pMD)[5] = ENDIANNESS32(HASH_VALUE(pState)[5]);
   ((Ipp32u*)pMD)[6] = ENDIANNESS32(HASH_VALUE(pState)[6]);
   ((Ipp32u*)pMD)[7] = ENDIANNESS32(HASH_VALUE(pState)[7]);

   /* re-init hash value */
   HAHS_BUFFIDX(pState) = 0;
   HASH_LENLO(pState) = 0;
   sha256_hashInit(HASH_VALUE(pState));

   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsSHA224Final,(Ipp8u* pMD, IppsSHA224State* pState))
{
   /* test state pointer and ID */
   IPP_BAD_PTR1_RET(pState);
   pState = (IppsSHA256State*)( IPP_ALIGNED_PTR(pState, SHA256_ALIGNMENT) );
   IPP_BADARG_RET(idCtxSHA256 !=HASH_CTX_ID(pState), ippStsContextMatchErr);

   /* test digest pointer */
   IPP_BAD_PTR1_RET(pMD);

   cpFinalizeSHA256(HASH_VALUE(pState), HASH_BUFF(pState), HAHS_BUFFIDX(pState), HASH_LENLO(pState));
   /* convert hash into big endian */
   ((Ipp32u*)pMD)[0] = ENDIANNESS32(HASH_VALUE(pState)[0]);
   ((Ipp32u*)pMD)[1] = ENDIANNESS32(HASH_VALUE(pState)[1]);
   ((Ipp32u*)pMD)[2] = ENDIANNESS32(HASH_VALUE(pState)[2]);
   ((Ipp32u*)pMD)[3] = ENDIANNESS32(HASH_VALUE(pState)[3]);
   ((Ipp32u*)pMD)[4] = ENDIANNESS32(HASH_VALUE(pState)[4]);
   ((Ipp32u*)pMD)[5] = ENDIANNESS32(HASH_VALUE(pState)[5]);
   ((Ipp32u*)pMD)[6] = ENDIANNESS32(HASH_VALUE(pState)[6]);

   /* re-init hash value */
   HAHS_BUFFIDX(pState) = 0;
   HASH_LENLO(pState) = 0;
   sha224_hashInit(HASH_VALUE(pState));

   return ippStsNoErr;
}


/*F*
//    Name: ippsSHA256GetTag
//          ippsSHA224GetTag
//
// Purpose: Compute digest based on current state.
//          Note, that futher digest update is possible
//
// Returns:                Reason:
//    ippStsNullPtrErr        pTag == NULL
//                            pState == NULL
//    ippStsContextMatchErr   pState->idCtx != idCtxSHA256
//    ippStsLengthErr         max_SHA_digestLen < tagLen <1
//    ippStsNoErr             no errors
//
// Parameters:
//    pTag        address of the output digest
//    tagLen      length of digest
//    pState      pointer to the SHS state
//
*F*/
IPPFUN(IppStatus, ippsSHA256GetTag,(Ipp8u* pTag, Ipp32u tagLen, const IppsSHA256State* pState))
{
   /* test state pointer and ID */
   IPP_BAD_PTR1_RET(pState);
   pState = (IppsSHA256State*)( IPP_ALIGNED_PTR(pState, SHA256_ALIGNMENT) );
   IPP_BADARG_RET(idCtxSHA256 !=HASH_CTX_ID(pState), ippStsContextMatchErr);

   /* test digest pointer */
   IPP_BAD_PTR1_RET(pTag);
   IPP_BADARG_RET((tagLen<1)||(sizeof(DigestSHA256)<tagLen), ippStsLengthErr);

   {
      DigestSHA256 digest;
      CopyBlock(HASH_VALUE(pState), digest, sizeof(DigestSHA256));
      cpFinalizeSHA256(digest, HASH_BUFF(pState), HAHS_BUFFIDX(pState), HASH_LENLO(pState));
      digest[0] = ENDIANNESS32(digest[0]);
      digest[1] = ENDIANNESS32(digest[1]);
      digest[2] = ENDIANNESS32(digest[2]);
      digest[3] = ENDIANNESS32(digest[3]);
      digest[4] = ENDIANNESS32(digest[4]);
      digest[5] = ENDIANNESS32(digest[5]);
      digest[6] = ENDIANNESS32(digest[6]);
      digest[7] = ENDIANNESS32(digest[7]);
      CopyBlock(digest, pTag, tagLen);

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsSHA224GetTag,(Ipp8u* pTag, Ipp32u tagLen, const IppsSHA224State* pState))
{
   /* test state pointer and ID */
   IPP_BAD_PTR1_RET(pState);
   pState = (IppsSHA256State*)( IPP_ALIGNED_PTR(pState, SHA256_ALIGNMENT) );
   IPP_BADARG_RET(idCtxSHA256 !=HASH_CTX_ID(pState), ippStsContextMatchErr);

   /* test digest pointer */
   IPP_BAD_PTR1_RET(pTag);
   IPP_BADARG_RET((tagLen<1)||(sizeof(DigestSHA224)<tagLen), ippStsLengthErr);

   {
      DigestSHA256 digest;
      CopyBlock(HASH_VALUE(pState), digest, sizeof(DigestSHA256));
      cpFinalizeSHA256(digest, HASH_BUFF(pState), HAHS_BUFFIDX(pState), HASH_LENLO(pState));
      digest[0] = ENDIANNESS32(digest[0]);
      digest[1] = ENDIANNESS32(digest[1]);
      digest[2] = ENDIANNESS32(digest[2]);
      digest[3] = ENDIANNESS32(digest[3]);
      digest[4] = ENDIANNESS32(digest[4]);
      digest[5] = ENDIANNESS32(digest[5]);
      digest[6] = ENDIANNESS32(digest[6]);
      digest[7] = ENDIANNESS32(digest[7]);
      CopyBlock(digest, pTag, tagLen);

      return ippStsNoErr;
   }
}


static IppStatus cpSHA256MessageDigest(DigestSHA256 hash, const Ipp8u* pMsg, int msgLen, const DigestSHA256 IV)
{
   /* test digest pointer */
   IPP_BAD_PTR1_RET(hash);
   /* test message length */
   IPP_BADARG_RET((msgLen<0), ippStsLengthErr);
   /* test message pointer */
   IPP_BADARG_RET((msgLen && !pMsg), ippStsNullPtrErr);

   {
      /* select processing function */
      #if (_SHA_NI_ENABLING_==_FEATURE_ON_)
      cpHashProc updateFunc = UpdateSHA256ni;
      #elif (_SHA_NI_ENABLING_==_FEATURE_TICKTOCK_)
      cpHashProc updateFunc = IsFeatureEnabled(SHA_NI_ENABLED)? UpdateSHA256ni : UpdateSHA256;
      #else
      cpHashProc updateFunc = UpdateSHA256;
      #endif

      /* message length in the multiple MBS and the rest */
      int msgLenBlks = msgLen & (-MBS_SHA256);
      int msgLenRest = msgLen - msgLenBlks;

      /* init hash */
      hash[0] = IV[0];
      hash[1] = IV[1];
      hash[2] = IV[2];
      hash[3] = IV[3];
      hash[4] = IV[4];
      hash[5] = IV[5];
      hash[6] = IV[6];
      hash[7] = IV[7];

      /* process main part of the message */
      if(msgLenBlks) {
         updateFunc(hash, pMsg, msgLenBlks, sha256_cnt);
         pMsg += msgLenBlks;
      }

      cpFinalizeSHA256(hash, pMsg, msgLenRest, msgLen);
      hash[0] = ENDIANNESS32(hash[0]);
      hash[1] = ENDIANNESS32(hash[1]);
      hash[2] = ENDIANNESS32(hash[2]);
      hash[3] = ENDIANNESS32(hash[3]);
      hash[4] = ENDIANNESS32(hash[4]);
      hash[5] = ENDIANNESS32(hash[5]);
      hash[6] = ENDIANNESS32(hash[6]);
      hash[7] = ENDIANNESS32(hash[7]);

      return ippStsNoErr;
   }
}

/*F*
//    Name: ippsSHA256MessageDigest,
//          ippsSHA224MessageDigest
//
// Purpose: Digest of the whole message.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pMsg == NULL
//                            pDigest == NULL
//    ippStsLengthErr         len <0
//    ippStsNoErr             no errors
//
// Parameters:
//    pMsg        pointer to the input message
//    len         input message length
//    pMD         address of the output digest
//
*F*/
IPPFUN(IppStatus, ippsSHA256MessageDigest,(const Ipp8u* pMsg, int msgLen, Ipp8u* pMD))
{
   /* test digest pointer */
   IPP_BAD_PTR1_RET(pMD);

   {
      DigestSHA256 hash;
      IppStatus sts = cpSHA256MessageDigest(hash, pMsg, msgLen, sha256_iv);
      if(ippStsNoErr==sts)
         CopyBlock(hash, pMD, IPP_SHA256_DIGEST_BITSIZE/BYTESIZE);
      return sts;
   }
}

IPPFUN(IppStatus, ippsSHA224MessageDigest,(const Ipp8u* pMsg, int msgLen, Ipp8u* pMD))
{
   /* test digest pointer */
   IPP_BAD_PTR1_RET(pMD);

   {
      DigestSHA256 hash;
      IppStatus sts = cpSHA256MessageDigest(hash, pMsg, msgLen, sha224_iv);
      if(ippStsNoErr==sts)
         CopyBlock(hash, pMD, IPP_SHA224_DIGEST_BITSIZE/BYTESIZE);
      return sts;
   }
}


/*
// available SHA256 methods
*/
IPPFUN( const IppsHashMethod*, ippsHashMethod_SHA256, (void) )
{
   static IppsHashMethod method = {
      ippHashAlg_SHA256,
      IPP_SHA256_DIGEST_BITSIZE/8,
      MBS_SHA256,
      MLR_SHA256,
      sha256_hashInit,
      sha256_hashUpdate,
      sha256_hashOctString,
      sha256_msgRep
   };
   return &method;
}

IPPFUN( const IppsHashMethod*, ippsHashMethod_SHA256_NI, (void) )
{
   #if (_SHA_NI_ENABLING_==_FEATURE_TICKTOCK_ || _SHA_NI_ENABLING_==_FEATURE_ON_)
   static IppsHashMethod method = {
      ippHashAlg_SHA256,
      IPP_SHA256_DIGEST_BITSIZE/8,
      MBS_SHA256,
      MLR_SHA256,
      sha256_hashInit,
      sha256_ni_hashUpdate,
      sha256_hashOctString,
      sha256_msgRep
   };
   return &method;
   #else
   return NULL;
   #endif
}

IPPFUN( const IppsHashMethod*, ippsHashMethod_SHA256_TT, (void) )
{
   static IppsHashMethod method = {
      ippHashAlg_SHA256,
      IPP_SHA256_DIGEST_BITSIZE/8,
      MBS_SHA256,
      MLR_SHA256,
      sha256_hashInit,
      sha256_hashUpdate,
      sha256_hashOctString,
      sha256_msgRep
   };
   #if (_SHA_NI_ENABLING_==_FEATURE_TICKTOCK_ || _SHA_NI_ENABLING_==_FEATURE_ON_)
   if(IsFeatureEnabled(SHA_NI_ENABLED))
      method.hashUpdate = sha256_ni_hashUpdate;
   #endif
   return &method;
}

/*
// available SHA224 methods
*/
IPPFUN( const IppsHashMethod*, ippsHashMethod_SHA224, (void) )
{
   static IppsHashMethod method = {
      ippHashAlg_SHA224,
      IPP_SHA224_DIGEST_BITSIZE/8,
      MBS_SHA256,
      MLR_SHA256,
      sha224_hashInit,
      sha256_hashUpdate,
      sha224_hashOctString,
      sha256_msgRep
   };
   return &method;
}

IPPFUN( const IppsHashMethod*, ippsHashMethod_SHA224_NI, (void) )
{
   #if (_SHA_NI_ENABLING_==_FEATURE_TICKTOCK_ || _SHA_NI_ENABLING_==_FEATURE_ON_)
   static IppsHashMethod method = {
      ippHashAlg_SHA224,
      IPP_SHA224_DIGEST_BITSIZE/8,
      MBS_SHA256,
      MLR_SHA256,
      sha224_hashInit,
      sha256_ni_hashUpdate,
      sha224_hashOctString,
      sha256_msgRep
   };
   return &method;
   #else
   return NULL;
   #endif
}

IPPFUN( const IppsHashMethod*, ippsHashMethod_SHA224_TT, (void) )
{
   static IppsHashMethod method = {
      ippHashAlg_SHA224,
      IPP_SHA224_DIGEST_BITSIZE/8,
      MBS_SHA256,
      MLR_SHA256,
      sha224_hashInit,
      sha256_hashUpdate,
      sha224_hashOctString,
      sha256_msgRep
   };
   #if (_SHA_NI_ENABLING_==_FEATURE_TICKTOCK_ || _SHA_NI_ENABLING_==_FEATURE_ON_)
   if(IsFeatureEnabled(SHA_NI_ENABLED))
      method.hashUpdate = sha256_ni_hashUpdate;
   #endif
   return &method;
}
