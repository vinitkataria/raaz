{-# LANGUAGE ForeignFunctionInterface #-}
{-# CFILES raaz/curves/cportable/curve25519-donna-c64.c #-}

module Raaz.Curves.EC25519.CPortable
        ( cGenerateParamsEC25519,
          cCalculateSecretEC25519
        ) where

import Data.Bits
import Data.Char

import Foreign.Ptr
import Foreign.C.Types
import Foreign.C.String
--import Foreign.ForeignPtr hiding (unsafeForeignPtrToPtr)
--import Foreign.ForeignPtr.Unsafe
import Foreign.Marshal.Array

--import System.Entropy

import Raaz.Curves.EC25519.Types
import Raaz.Curves.P25519.Internal
import Raaz.KeyExchange

--import Data.ByteString.Internal as SI
--import Data.ByteString.Unsafe   as SU
--import Data.Word

foreign import ccall unsafe "curve25519-donna-c64.h curve25519_donna"
  c_curve25519_donna :: Ptr CUChar -> Ptr CUChar -> Ptr CUChar -> IO CInt

getSecretFromRandom :: P25519 -> P25519
getSecretFromRandom (P25519 xrandom) = privnum
  where
    temp1 = (((1 `shiftL` 248) - 1) `shiftL` 8) + 248
    -- temp1: (256 bit number with 248 1's followed by 248)
    temp2 = xrandom .&. temp1
    -- (Rightmost-byte `AND` with 248)
    temp3 = (127 `shiftL` 248) .|. ((1 `shiftL` 248) - 1)
    -- temp3: (256 bit number with 127 followed by 248 1's)
    temp4 = temp2 .&. temp3
    -- (Leftmost-byte `AND` with 127)
    temp5 = (64 `shiftL` 248)
    -- temp5: (256 bit number with 64 followed by 248 1's)
    temp6 = temp4 .|. temp5
    -- (Leftmost-byte `OR` with 64)
    privnum = P25519 (temp6)

cGenerateParamsEC25519 :: P25519 -> IO (PrivateNum P25519, PublicNum P25519)
cGenerateParamsEC25519 (P25519 randomnum) = do
  let getList 0 list   = list
      getList n list   = getList (n `shiftR` 8) (list ++ [n .&. 255])
      getcuCharList    = map (castCharToCUChar . chr . fromIntegral)
      secretList       = getcuCharList $ (getList randomnum [])
      (P25519 basenum) = curve25519Gx
      baseList         = getcuCharList $ (getList basenum [])
  secret <- newArray secretList
  base   <- newArray baseList
  public <- newArray ((replicate 32 0) :: [CUChar])
  _ <- c_curve25519_donna public secret base
  pubkey <- peekArray 32 public
  let getIntegerList = map (toInteger . ord . castCUCharToChar)
      addInt num d = 256*num + d
      integerFromList = foldl addInt 0
      getInteger = integerFromList . getIntegerList
      privnum = getSecretFromRandom (P25519 randomnum)
      publicnum = P25519 $ getInteger pubkey
  return (PrivateNum privnum, PublicNum publicnum)

cCalculateSecretEC25519 :: PrivateNum P25519
                       -> PublicNum P25519
                       -> IO (SharedSecret P25519)
cCalculateSecretEC25519 (PrivateNum privnum) (PublicNum publicnum) = do
  let getList 0 list     = list
      getList n list     = getList (n `shiftR` 8) (list ++ [n .&. 255])
      getcuCharList      = map (castCharToCUChar . chr . fromIntegral)
      (P25519 secretnum) = privnum
      secretList         = getcuCharList $ (getList secretnum [])
      (P25519 basenum)   = publicnum
      baseList           = getcuCharList $ (getList basenum [])
  secret <- newArray secretList
  base   <- newArray baseList
  shared <- newArray ((replicate 32 0) :: [CUChar])
  _ <- c_curve25519_donna shared secret base
  sharedkey <- peekArray 32 shared
  let getIntegerList = map (toInteger . ord . castCUCharToChar)
      addInt num d = 256*num + d
      integerFromList = foldl addInt 0
      getInteger = integerFromList . getIntegerList
      sharedsecret = P25519 $ getInteger sharedkey
  return (SharedSecret sharedsecret)
