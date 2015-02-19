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

cGenerateParamsEC25519 :: Integer -> IO (Secret25519, PublicToken25519)
cGenerateParamsEC25519 randomnum = do
  let getList 0 list = list ++ (replicate (32 - length list) 0)
      getList n list = getList (n `shiftR` 8) (list ++ [n .&. 255])
      getcuCharList  = map (castCharToCUChar . chr . fromIntegral)
      secretList     = getcuCharList $ (getList randomnum [])
      basenum        = curve25519Gx
      baseList       = getcuCharList $ (getList basenum [])
  secret <- newArray secretList
  base   <- newArray baseList
  public <- newArray ((replicate 32 0) :: [CUChar])
  _ <- c_curve25519_donna public secret base
  pubkey <- peekArray 32 public
  let getIntegerList = map (toInteger . ord . castCUCharToChar)
      addInt num d = 256*num + d
      integerFromList = foldl addInt 0
      getInteger = integerFromList . reverse . getIntegerList
      privnum = integerToP25519 (getSecretFromRandom randomnum)
      publicnum = integerToP25519 (getInteger pubkey)
  --putStrLn $ showHex publicnum ""
  return (Secret25519 privnum, PublicToken25519 publicnum)

cCalculateSecretEC25519 :: Secret25519
                       -> PublicToken25519
                       -> IO (SharedSecret25519)
cCalculateSecretEC25519 (Secret25519 privnum) (PublicToken25519 publicnum) = do
  let getList 0 list = list ++ (replicate (32 - length list) 0)
      getList n list = getList (n `shiftR` 8) (list ++ [n .&. 255])
      getcuCharList  = map (castCharToCUChar . chr . fromIntegral)
      secretnum      = p25519toInteger privnum
      secretList     = getcuCharList $ (getList secretnum [])
      basenum        = p25519toInteger publicnum
      baseList       = getcuCharList $ (getList basenum [])
  secret <- newArray secretList
  base   <- newArray baseList
  shared <- newArray ((replicate 32 0) :: [CUChar])
  _ <- c_curve25519_donna shared secret base
  sharedkey <- peekArray 32 shared
  let getIntegerList = map (toInteger . ord . castCUCharToChar)
      addInt num d = 256*num + d
      integerFromList = foldl addInt 0
      getInteger = integerFromList . reverse . getIntegerList
      sharedsecret = integerToP25519 (getInteger sharedkey)
  --putStrLn $ showHex sharedsecret ""
  return (SharedSecret25519 sharedsecret)
