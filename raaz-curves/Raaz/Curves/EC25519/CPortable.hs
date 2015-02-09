{-# LANGUAGE ForeignFunctionInterface #-}
{-# OPTIONS_GHC -fno-warn-orphans     #-}
{-# CFILES raaz/curves/cportable/curve25519-donna-c64.c #-}

module Raaz.Curves.EC25519.CPortable
        ( cGenerateParamsEC25519,
          cCalculateSecretEC25519
        ) where

import Data.Bits
import Data.Char
import Numeric ()

import Foreign.Ptr
import Foreign.C.Types
import Foreign.C.String
import Foreign.Marshal.Array

import Raaz.Curves.EC25519.Types()
import Raaz.Curves.P25519.Internal

foreign import ccall unsafe
  "curve25519-donna-c64.c curve25519_donna"
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

cGenerateParamsEC25519 :: P25519 -> IO (Secret25519, PublicToken25519)
cGenerateParamsEC25519 (P25519 randomnum) = do
  let getList 0 list   = list ++ (replicate (32 - length list) 0)
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
      getInteger = integerFromList . reverse . getIntegerList
      privnum = getSecretFromRandom (P25519 randomnum)
      publicnum = P25519 $ getInteger pubkey
  --putStrLn $ showHex publicnum ""
  return (Secret25519 privnum, PublicToken25519 publicnum)

cCalculateSecretEC25519 :: Secret25519
                       -> PublicToken25519
                       -> IO (SharedSecret25519)
cCalculateSecretEC25519 (Secret25519 privnum) (PublicToken25519 publicnum) = do
  let getList 0 list     = list ++ (replicate (32 - length list) 0)
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
      getInteger = integerFromList . reverse . getIntegerList
      sharedsecret = P25519 $ getInteger sharedkey
  --putStrLn $ showHex sharedsecret ""
  return (SharedSecret25519 sharedsecret)
