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
//     Security Hash Standard
//     General Functionality
// 
//  Contents:
//     ippsHashGetSize()
//     ippsHashInit()
//     ippsHashPack()
//     ippsHashUnpack()
//     ippsHashDuplicate()
//     ippsHashUpdate()
//     ippsHashGetTag()
//     ippsHashFinal()
//     ippsHashMessage()
// 
// 
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcphash.h"
#include "pcptool.h"


/*F*
//    Name: ippsHashGetSize
//
// Purpose: Returns size (bytes) of IppsHashState state.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize       pointer to state size
//
*F*/
IPPFUN(IppStatus, ippsHashGetSize,(int* pSize))
{
   /* test pointers */
   IPP_BAD_PTR1_RET(pSize);

   *pSize = sizeof(IppsHashState);
   return ippStsNoErr;
}


/*F*
//    Name: ippsHashInit
//
// Purpose: Init Hash state.
//
// Returns:                Reason:
//    ippStsNullPtrErr           pState == NULL
//    ippStsNotSupportedModeErr  if algID is not match to supported hash alg
//    ippStsNoErr                no errors
//
// Parameters:
//    pCtx     pointer to the Hash state
//    algID    hash alg ID
//
*F*/
int cpReInitHash(IppsHashState* pCtx, IppHashAlgId algID)
{
   int hashIvSize = cpHashIvSize(algID);
   const Ipp8u* iv = cpHashIV[algID];

   HASH_LENLO(pCtx) = CONST_64(0);
   HASH_LENHI(pCtx) = CONST_64(0);
   HAHS_BUFFIDX(pCtx) = 0;
   CopyBlock(iv, HASH_VALUE(pCtx), hashIvSize);

   return hashIvSize;
}

/*
// hash alg default processing functions and opt argument
*/
static cpHashProc cpHashProcFunc[] = {
   (cpHashProc)NULL,

   #if defined(_ENABLE_ALG_SHA1_)
      #if(_SHA_NI_ENABLING_==_FEATURE_ON_)
      UpdateSHA1ni,
      #else
      UpdateSHA1,
      #endif
   #else
   NULL,
   #endif

   #if defined(_ENABLE_ALG_SHA256_)
      #if(_SHA_NI_ENABLING_==_FEATURE_ON_)
      UpdateSHA256ni,
      #else
      UpdateSHA256,
      #endif
   #else
   NULL,
   #endif

   #if defined(_ENABLE_ALG_SHA224_)
      #if(_SHA_NI_ENABLING_==_FEATURE_ON_)
      UpdateSHA256ni,
      #else
      UpdateSHA256,
      #endif
   #else
   NULL,
   #endif

   #if defined(_ENABLE_ALG_SHA512_)
   UpdateSHA512,
   #else
   NULL,
   #endif

   #if defined(_ENABLE_ALG_SHA384_)
   UpdateSHA512,
   #else
   NULL,
   #endif

   #if defined(_ENABLE_ALG_MD5_)
   UpdateMD5,
   #else
   NULL,
   #endif

   #if defined(_ENABLE_ALG_SM3_)
   UpdateSM3,
   #else
   NULL,
   #endif

   #if defined(_ENABLE_ALG_SHA512_224_)
   UpdateSHA512,
   #else
   NULL,
   #endif

   #if defined(_ENABLE_ALG_SHA512_256_)
   UpdateSHA512,
   #else
   NULL,
   #endif
};

#define cpInitHash OWNAPI(cpInitHash)
int cpInitHash(IppsHashState* pCtx, IppHashAlgId algID)
{
   /* setup default processing function */
   HASH_FUNC(pCtx) = cpHashProcFunc[algID];

   /* update default processing function if SHA-NI enabled */
   #if (_IPP>=_IPP_P8) || (_IPP32E>=_IPP32E_Y8)
   if( IsFeatureEnabled(SHA_NI_ENABLED) ) {

      #if defined(_ENABLE_ALG_SHA1_)
      if(ippHashAlg_SHA1==algID)
         HASH_FUNC(pCtx) = UpdateSHA1ni;
      #endif

      #if defined(_ENABLE_ALG_SHA256_) || defined(_ENABLE_ALG_SHA224_)
      if(ippHashAlg_SHA256==algID || ippHashAlg_SHA224==algID)
         HASH_FUNC(pCtx) = UpdateSHA256ni;
      #endif
   }
   #endif

   /* setup optional agr of processing function */
   HASH_FUNC_PAR(pCtx) = cpHashProcFuncOpt[algID];

   return cpReInitHash(pCtx, algID);
}

IPPFUN(IppStatus, ippsHashInit,(IppsHashState* pCtx, IppHashAlgId algID))
{
   /* get algorithm id */
   algID = cpValidHashAlg(algID);
   /* test hash alg */
   IPP_BADARG_RET(ippHashAlg_Unknown==algID, ippStsNotSupportedModeErr);

   /* test ctx pointer */
   IPP_BAD_PTR1_RET(pCtx);
   /* test hash alg */

   /* set ctx ID */
   HASH_CTX_ID(pCtx) = idCtxHash;
   HASH_ALG_ID(pCtx) = algID;

   /* init context */
   cpInitHash(pCtx, algID);
   return ippStsNoErr;
}


/*F*
//    Name: ippsHashPack
//
// Purpose: Copy initialized context to the buffer.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//                            pBuffer == NULL
//    ippStsContextMatchErr   pCtx->idCtx != idCtxHash
//    ippStsNoMemErr          bufSize < sizeof(IppsHashState)
//    ippStsNoErr             no errors
//
// Parameters:
//    pCtx        pointer hash state
//    pBuffer     pointer to the destination buffer
//    bufSize     size of the destination buffer
//
*F*/
IPPFUN(IppStatus, ippsHashPack,(const IppsHashState* pCtx, Ipp8u* pBuffer, int bufSize))
{
   /* test pointers */
   IPP_BAD_PTR2_RET(pCtx, pBuffer);
   /* test the context */
   IPP_BADARG_RET(!HASH_VALID_ID(pCtx), ippStsContextMatchErr);
   /* test buffer length */
   IPP_BADARG_RET((int)(sizeof(IppsHashState))>bufSize, ippStsNoMemErr);

   CopyBlock(pCtx, pBuffer, sizeof(IppsHashState));
   return ippStsNoErr;
}


/*F*
//    Name: ippsHashUnpack
//
// Purpose: Unpack buffer content into the initialized context.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//                            pBuffer == NULL
//    ippStsNoErr             no errors
//
// Parameters:
//    pBuffer     pointer to the source buffer
//    pCtx        pointer hash state
//
*F*/
IPPFUN(IppStatus, ippsHashUnpack,(const Ipp8u* pBuffer, IppsHashState* pCtx))
{
   /* test pointers */
   IPP_BAD_PTR2_RET(pCtx, pBuffer);

   CopyBlock(pBuffer, pCtx, sizeof(IppsHashState));
   return ippStsNoErr;
}


/*F*
//    Name: ippsHashDuplicate
//
// Purpose: Clone Hash context.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSrcCtx == NULL
//                            pDstCtx == NULL
//    ippStsContextMatchErr   pSrcCtx->idCtx != idCtxHash
//                            pDstCtx->idCtx != idCtxHash
//    ippStsNoErr             no errors
//
// Parameters:
//    pSrcCtx  pointer to the source Hash context
//    pDstCtx  pointer to the target Hash context
//
// Note:
//    pDstCtx may to be uninitialized by ippsHashInit()
//
*F*/
IPPFUN(IppStatus, ippsHashDuplicate,(const IppsHashState* pSrcCtx, IppsHashState* pDstCtx))
{
   /* test state pointers */
   IPP_BAD_PTR2_RET(pSrcCtx, pDstCtx);
   /* test states ID */
   IPP_BADARG_RET(!HASH_VALID_ID(pSrcCtx), ippStsContextMatchErr);

   /* copy state */
   CopyBlock(pSrcCtx, pDstCtx, sizeof(IppsHashState));
   return ippStsNoErr;
}


/*F*
//    Name: ippsHashUpdate
//
// Purpose: Updates intermediate hash value based on input stream.
//
// Returns:                   Reason:
//    ippStsNullPtrErr           pCtx == NULL
//    ippStsNullPtrErr           pSrc==0 but len!=0
//    ippStsContextMatchErr      pCtx->idCtx != idCtxHash
//    ippStsLengthErr            len <0
//    ippStsNoErr                no errors
//
// Parameters:
//    pSrc     pointer to the input stream
//    len      input stream length
//    pCtx     pointer to the Hash context
//
*F*/
__INLINE int IsExceedMsgLen(Ipp64u maxLo, Ipp64u maxHi, Ipp64u lenLo, Ipp64u lenHi)
{
   int isExceed = lenLo > maxLo;
   isExceed = (lenHi+isExceed) > maxHi;
   return isExceed;
}

IPPFUN(IppStatus, ippsHashUpdate,(const Ipp8u* pSrc, int len, IppsHashState* pCtx))
{
   /* test state pointer and ID */
   IPP_BAD_PTR1_RET(pCtx);
   /* test the context */
   IPP_BADARG_RET(!HASH_VALID_ID(pCtx), ippStsContextMatchErr);
   /* test input length */
   IPP_BADARG_RET((len<0 && pSrc), ippStsLengthErr);
   /* test source pointer */
   IPP_BADARG_RET((len && !pSrc), ippStsNullPtrErr);

   /* handle non empty input */
   if(len) {
      const cpHashAttr* pAttr = &cpHashAlgAttr[HASH_ALG_ID(pCtx)];

      /* test if size of message is being processed not exceeded yet */
      Ipp64u lenLo = HASH_LENLO(pCtx);
      Ipp64u lenHi = HASH_LENHI(pCtx);
      lenLo += len;
      if(lenLo < HASH_LENLO(pCtx)) lenHi++;
      if(IsExceedMsgLen(pAttr->msgLenMax[0],pAttr->msgLenMax[1], lenLo,lenHi))
         IPP_ERROR_RET(ippStsLengthErr);

      else {
         cpHashProc hashFunc = HASH_FUNC(pCtx);    /* processing function */
         const void* pParam = HASH_FUNC_PAR(pCtx); /* and it's addition params */
         int mbs = pAttr->msgBlkSize;              /* data block size */

         /*
         // processing
         */
         {
            int procLen;

            /* test if internal buffer is not empty */
            int n = HAHS_BUFFIDX(pCtx);
            if(n) {
               procLen = IPP_MIN(len, (mbs-n));
               CopyBlock(pSrc, HASH_BUFF(pCtx)+n, procLen);
               HAHS_BUFFIDX(pCtx) = n += procLen;

               /* block processing */
               if(mbs==n) {
                  hashFunc(HASH_VALUE(pCtx), HASH_BUFF(pCtx), mbs, pParam);
                  HAHS_BUFFIDX(pCtx) = 0;
               }

               /* update message pointer and length */
               pSrc += procLen;
               len  -= procLen;
            }

            /* main processing part */
            procLen = len & ~(mbs-1);
            if(procLen) {
               hashFunc(HASH_VALUE(pCtx), pSrc, procLen, pParam);
               pSrc += procLen;
               len  -= procLen;
            }

            /* rest of input message */
            if(len) {
               CopyBlock(pSrc, HASH_BUFF(pCtx), len);
               HAHS_BUFFIDX(pCtx) += len;
            }
         }

         /* update length of processed message */
         HASH_LENLO(pCtx) = lenLo;
         HASH_LENHI(pCtx) = lenHi;

         return ippStsNoErr;
      }
   }

   return ippStsNoErr;
}

static void cpComputeDigest(Ipp8u* pHashTag, int hashTagLen, const IppsHashState* pCtx)
{
   /* hash alg and parameters */
   cpHashProc hashFunc = HASH_FUNC(pCtx);    /* processing function */
   const void* pParam = HASH_FUNC_PAR(pCtx); /* and it's addition params */

   /* attributes */
   const cpHashAttr* pAttr = &cpHashAlgAttr[HASH_ALG_ID(pCtx)];
   int mbs = pAttr->msgBlkSize;              /* data block size */
   int ivSize = pAttr->ivSize;               /* size of hash's IV */
   int msgLenRepSize = pAttr->msgLenRepSize; /* length of the message representation */

   /* number of bytes in context buffer */
   int n = HAHS_BUFFIDX(pCtx);
   /* buffer and it actual length */
   Ipp8u buffer[MBS_HASH_MAX*2];
   int bufferLen = n < (mbs-msgLenRepSize)? mbs : mbs*2;

   /* copy current hash value */
   cpHash hash;
   CopyBlock(HASH_VALUE(pCtx), hash, ivSize);

   /* copy of state's buffer */
   CopyBlock(HASH_BUFF(pCtx), buffer, n);
   /* end of message bit */
   buffer[n++] = 0x80;
   /* padd buffer */
   PaddBlock(0, buffer+n, bufferLen-n-msgLenRepSize);

   /* message length representation in bits (remember about big endian) */
   {
      /* convert processed message length bytes ->bits */
      Ipp64u lo = HASH_LENLO(pCtx);
      Ipp64u hi = HASH_LENHI(pCtx);
      hi = LSL64(hi,3) | LSR64(lo,63-3);
      lo = LSL64(lo,3);

      if(msgLenRepSize>(int)(sizeof(Ipp64u))) {
      #if (IPP_ENDIAN == IPP_BIG_ENDIAN)
         ((Ipp64u*)(buffer+bufferLen))[-2] = hi;
      #else
         ((Ipp64u*)(buffer+bufferLen))[-2] = ENDIANNESS64(hi);
      #endif
      }

      /* recall about MD5 specific */
      if(ippHashAlg_MD5!=HASH_ALG_ID(pCtx)) {
         #if (IPP_ENDIAN == IPP_BIG_ENDIAN)
         ((Ipp64u*)(buffer+bufferLen))[-1] = lo;
         #else
         ((Ipp64u*)(buffer+bufferLen))[-1] = ENDIANNESS64(lo);
         #endif
      }
      else {
         #if (IPP_ENDIAN == IPP_BIG_ENDIAN)
         ((Ipp64u*)(buffer+bufferLen))[-1] = ENDIANNESS64(lo);
         #else
         ((Ipp64u*)(buffer+bufferLen))[-1] = lo;
         #endif
      }
   }

   /* copmplete hash computation */
   hashFunc(hash, buffer, bufferLen, pParam);

   /* store digest into the user buffer (remember digest in big endian) */
   if(msgLenRepSize>(int)(sizeof(Ipp64u))) {
      /* ippHashAlg_SHA384, ippHashAlg_SHA512, ippHashAlg_SHA512_224 and ippHashAlg_SHA512_256 */
      hash[0] = ENDIANNESS64(hash[0]);
      hash[1] = ENDIANNESS64(hash[1]);
      hash[2] = ENDIANNESS64(hash[2]);
      hash[3] = ENDIANNESS64(hash[3]);
      hash[4] = ENDIANNESS64(hash[4]);
      hash[5] = ENDIANNESS64(hash[5]);
      hash[6] = ENDIANNESS64(hash[6]);
      hash[7] = ENDIANNESS64(hash[7]);
   }
   else if(ippHashAlg_MD5!=HASH_ALG_ID(pCtx)) {
      ((Ipp32u*)hash)[0] = ENDIANNESS32(((Ipp32u*)hash)[0]);
      ((Ipp32u*)hash)[1] = ENDIANNESS32(((Ipp32u*)hash)[1]);
      ((Ipp32u*)hash)[2] = ENDIANNESS32(((Ipp32u*)hash)[2]);
      ((Ipp32u*)hash)[3] = ENDIANNESS32(((Ipp32u*)hash)[3]);
      ((Ipp32u*)hash)[4] = ENDIANNESS32(((Ipp32u*)hash)[4]);
      if(ippHashAlg_SHA1!=HASH_ALG_ID(pCtx)) {
         ((Ipp32u*)hash)[5] = ENDIANNESS32(((Ipp32u*)hash)[5]);
         ((Ipp32u*)hash)[6] = ENDIANNESS32(((Ipp32u*)hash)[6]);
         ((Ipp32u*)hash)[7] = ENDIANNESS32(((Ipp32u*)hash)[7]);
      }
   }
   CopyBlock(hash, pHashTag, hashTagLen);
}


/*F*
//    Name: ippsHashGetTag
//
// Purpose: Compute digest based on current state.
//          Note, that futher digest update is possible
//
// Returns:                   Reason:
//    ippStsNullPtrErr           pTag == NULL
//                               pCtx == NULL
//    ippStsContextMatchErr      pCtx->idCtx != idCtxHash
//    ippStsLengthErr            hashSize < tagLen <1
//    ippStsNoErr                no errors
//
// Parameters:
//    pTag     address of the output digest
//    tagLen   length of digest
//    pCtx     pointer to the SHS state
//
*F*/
IPPFUN(IppStatus, ippsHashGetTag,(Ipp8u* pTag, int tagLen, const IppsHashState* pCtx))
{
   /* test state pointer and ID */
   IPP_BAD_PTR2_RET(pTag, pCtx);
   /* test the context */
   IPP_BADARG_RET(!HASH_VALID_ID(pCtx), ippStsContextMatchErr);

   {
      /* size of hash */
      int hashSize = cpHashAlgAttr[HASH_ALG_ID(pCtx)].hashSize;
      if(tagLen<1||hashSize<tagLen) IPP_ERROR_RET(ippStsLengthErr);

      cpComputeDigest(pTag, tagLen, pCtx);
      return ippStsNoErr;
   }
}

/*F*
//    Name: ippsHashFinal
//
// Purpose: Complete message digesting and return digest.
//
// Returns:                   Reason:
//    ippStsNullPtrErr           pMD == NULL
//                               pCtx == NULL
//    ippStsContextMatchErr      pCtx->idCtx != idCtxHash
//    ippStsNoErr                no errors
//
// Parameters:
//    pMD   address of the output digest
//    pCtx  pointer to the SHS state
//
*F*/
IPPFUN(IppStatus, ippsHashFinal,(Ipp8u* pMD, IppsHashState* pCtx))
{
   /* test state pointer and ID */
   IPP_BAD_PTR2_RET(pMD, pCtx);
   /* test the context */
   IPP_BADARG_RET(!HASH_VALID_ID(pCtx), ippStsContextMatchErr);

   {
      IppHashAlgId algID = HASH_ALG_ID(pCtx);
      int hashSize = cpHashAlgAttr[algID].hashSize;

      cpComputeDigest(pMD, hashSize, pCtx);
      cpReInitHash(pCtx, algID);

      return ippStsNoErr;
   }
}


/*F*
//    Name: ippsHashMessage
//
// Purpose: Hash of the whole message.
//
// Returns:                Reason:
//    ippStsNullPtrErr           pMD == NULL
//                               pMsg == NULL but msgLen!=0
//    ippStsLengthErr            msgLen <0
//    ippStsNotSupportedModeErr  if algID is not match to supported hash alg
//    ippStsNoErr                no errors
//
// Parameters:
//    pMsg        pointer to the input message
//    msgLen      input message length
//    pMD         address of the output digest
//    algID       hash alg ID
//
*F*/
IPPFUN(IppStatus, ippsHashMessage,(const Ipp8u* pMsg, int msgLen, Ipp8u* pMD, IppHashAlgId algID))
{
   /* get algorithm id */
   algID = cpValidHashAlg(algID);
   /* test hash alg */
   IPP_BADARG_RET(ippHashAlg_Unknown==algID, ippStsNotSupportedModeErr);

   /* test digest pointer */
   IPP_BAD_PTR1_RET(pMD);
   /* test message length */
   IPP_BADARG_RET((msgLen<0), ippStsLengthErr);
   /* test message pointer */
   IPP_BADARG_RET((msgLen && !pMsg), ippStsNullPtrErr);

   {
      /* processing function and parameter */
      cpHashProc hashFunc = cpHashProcFunc[algID];
      const void* pParam = cpHashProcFuncOpt[algID];

      /* attributes */
      const cpHashAttr* pAttr = &cpHashAlgAttr[algID];
      int mbs = pAttr->msgBlkSize;              /* data block size */
      int ivSize = pAttr->ivSize;               /* size of hash's IV */
      int hashSize = pAttr->hashSize;           /* hash size */
      int msgLenRepSize = pAttr->msgLenRepSize; /* length of the message representation */

      /* message bitlength representation */
      Ipp64u msgLenBits = (Ipp64u)msgLen*8;
      /* length of main message part */
      int msgLenBlks = msgLen & (-mbs);
      /* rest of message length */
      int msgLenRest = msgLen - msgLenBlks;

      /* end of message buffer */
      Ipp8u buffer[MBS_HASH_MAX*2];
      int bufferLen = (msgLenRest < (mbs-msgLenRepSize))? mbs : mbs*2;

      /* init hash */
      cpHash hash;
      const Ipp8u* iv = cpHashIV[algID];
      CopyBlock(iv, hash, ivSize);

      /*construct last messge block(s) */
      #define MSG_LEN_REP  (sizeof(Ipp64u))

      /* copy end of message */
      CopyBlock(pMsg+msgLen-msgLenRest, buffer, msgLenRest);
      /* end of message bit */
      buffer[msgLenRest++] = 0x80;
      /* padd buffer */
      PaddBlock(0, buffer+msgLenRest, bufferLen-msgLenRest-MSG_LEN_REP);
      /* copy message bitlength representation */
      if(ippHashAlg_MD5!=algID)
         msgLenBits = ENDIANNESS64(msgLenBits);
      ((Ipp64u*)(buffer+bufferLen))[-1] = msgLenBits;

      #undef MSG_LEN_REP

      /* message processing */
      if(msgLenBlks)
         hashFunc(hash, pMsg, msgLenBlks, pParam);
      hashFunc(hash, buffer, bufferLen, pParam);

      /* store digest into the user buffer (remember digest in big endian) */
      if(msgLenRepSize > (int)(sizeof(Ipp64u))) {
         /* ippHashAlg_SHA384, ippHashAlg_SHA512, ippHashAlg_SHA512_224 and ippHashAlg_SHA512_256 */
         hash[0] = ENDIANNESS64(hash[0]);
         hash[1] = ENDIANNESS64(hash[1]);
         hash[2] = ENDIANNESS64(hash[2]);
         hash[3] = ENDIANNESS64(hash[3]);
         hash[4] = ENDIANNESS64(hash[4]);
         hash[5] = ENDIANNESS64(hash[5]);
         hash[6] = ENDIANNESS64(hash[6]);
         hash[7] = ENDIANNESS64(hash[7]);
      }
      else if(ippHashAlg_MD5!=algID) {
         /* ippHashAlg_SHA1, ippHashAlg_SHA224, ippHashAlg_SHA256 and ippHashAlg_SM3 */
         ((Ipp32u*)hash)[0] = ENDIANNESS32(((Ipp32u*)hash)[0]);
         ((Ipp32u*)hash)[1] = ENDIANNESS32(((Ipp32u*)hash)[1]);
         ((Ipp32u*)hash)[2] = ENDIANNESS32(((Ipp32u*)hash)[2]);
         ((Ipp32u*)hash)[3] = ENDIANNESS32(((Ipp32u*)hash)[3]);
         ((Ipp32u*)hash)[4] = ENDIANNESS32(((Ipp32u*)hash)[4]);
         ((Ipp32u*)hash)[5] = ENDIANNESS32(((Ipp32u*)hash)[5]);
         ((Ipp32u*)hash)[6] = ENDIANNESS32(((Ipp32u*)hash)[6]);
         ((Ipp32u*)hash)[7] = ENDIANNESS32(((Ipp32u*)hash)[7]);
      }
      CopyBlock(hash, pMD, hashSize);

      return ippStsNoErr;
   }
}
