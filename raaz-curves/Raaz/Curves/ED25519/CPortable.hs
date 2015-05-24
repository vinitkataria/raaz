{- |

This module gives the recommended implementation of the DH functions
over Curve25519. This uses the ed25519 implementation from
https://github.com/agl/curve25519-donna/.

-}

{-# LANGUAGE ForeignFunctionInterface  #-}
{-# LANGUAGE TypeFamilies              #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# OPTIONS_GHC -fno-warn-orphans      #-}
{-# LANGUAGE CPP                      #-}
{-# CFILES raaz/curves/cportable/ed25519/ed25519.c #-}

#include "MachDeps.h"

module Raaz.Curves.ED25519.CPortable
        ( createKeypair
        , createKeypairGivenRandom
        , skTest
        ) where

import Control.Monad   (void)
import Foreign.Ptr
import Foreign.C.Types

import           Foreign.ForeignPtr       (withForeignPtr)
import           Foreign.Marshal.Alloc    (alloca)
import           Foreign.Storable

import Raaz.Core.Types
import Raaz.Core.Util.Ptr (byteSize, allocaBuffer)
import Raaz.Curves.ED25519.Internal
import Raaz.Number

import           System.IO.Unsafe         (unsafePerformIO)

import           Data.ByteString          as S
import           Data.ByteString.Internal as SI
import           Data.ByteString.Unsafe   as SU
import           Data.Word
import           Data.Bits
import qualified Data.Vector.Unboxed                  as VU

import Foreign.Ptr

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Types

import Raaz.Curves.ED25519.Type
import Raaz.Curves.ED25519.Ref

import Control.Applicative
import Data.Bits
import Data.Word
import qualified Data.Vector.Unboxed as VU

import Raaz.Core.Types
import Raaz.Core.Util.Ptr
import Control.Monad       ( foldM )

foreign import ccall unsafe "ed25519_sign_keypair"
  c_crypto_sign_keypair :: CryptoPtr -> CryptoPtr -> IO CInt

foreign import ccall unsafe "ed25519_sign_keypair_given_random"
  c_crypto_sign_keypair_given_random :: CryptoPtr -> CryptoPtr -> IO CInt

foreign import ccall unsafe "ed25519_sign"
-- @params *signedMsg, msg, msgLength, secretKey
  c_crypto_sign :: CryptoPtr -> CryptoPtr ->
                   CryptoPtr -> CULLong -> CryptoPtr -> IO CInt

foreign import ccall unsafe "ed25519_sign_open"
  c_crypto_sign_open :: Ptr Word8 -> Ptr CULLong ->
                        Ptr CChar -> CULLong -> Ptr CChar -> IO CInt

-- signRecommended :: SecretKey -> B.ByteString -> IO Signature
-- signRecommended sk msg = do
--   let sizeSK    = sizeOf (undefined :: W256)
--       sizeMsg   =
--       szBytes   = byteSize (undefined :: W256)
--       totalSize = szBytes * 2
--   allocaBuffer totalSize $ \ ptr -> do
--     store (ptr `plusPtr` size) w
--     void $ c_crypto_sign_keypair_given_random ptr (ptr `plusPtr` size)
--     pubkey <- load ptr
--     secret <- load (ptr `plusPtr` size)

-- #if WORD_SIZE_IN_BITS < 64
-- foreign import ccall unsafe
--   "curve25519-donna.c raaz_curve25519_donna_portable"
--    c_curve25519_donna :: CryptoPtr -> CryptoPtr -> CryptoPtr -> IO CInt
-- #else
-- foreign import ccall unsafe
--     "curve25519-donna-c64.c raaz_curve25519_donna_c64"
--      c_curve25519_donna :: CryptoPtr -> CryptoPtr -> CryptoPtr -> IO CInt
-- #endif
skTest :: IO ()
skTest = do
  let size      = sizeOf (undefined :: SecretKey)
      szBytes   = byteSize (undefined :: SecretKey)
      sk        = SecretKey (word256ToW256 0)
      SecretKey w = sk
  allocaBuffer szBytes $ \ ptr -> do
    print w
    store ptr sk
    (SecretKey key) <- load ptr
    print key
    return ()

createKeypair :: IO (SecretKey, PublicKey)
createKeypair = do
  let size      = sizeOf (undefined :: W256)
      szBytes   = byteSize (undefined :: W256)
      totalSize = szBytes * 2
  allocaBuffer totalSize $ \ ptr -> do
    void $ c_crypto_sign_keypair ptr (ptr `plusPtr` size)
    pubkey <- load ptr
    secret <- load (ptr `plusPtr` size)
    return (SecretKey secret, PublicKey pubkey)

createKeypairGivenRandom :: W256 -> IO (SecretKey, PublicKey)
createKeypairGivenRandom w@(W256 random) = do
  let size      = sizeOf (undefined :: W256)
      szBytes   = byteSize (undefined :: W256)
      totalSize = szBytes * 2
  allocaBuffer totalSize $ \ ptr -> do
    store (ptr `plusPtr` size) w
    void $ c_crypto_sign_keypair_given_random ptr (ptr `plusPtr` size)
    pubkey <- load ptr
    secret <- load (ptr `plusPtr` size)
    return (SecretKey secret, PublicKey pubkey)

-- foreign import ccall unsafe "ed25519_sign_open"
--   c_crypto_sign_open :: Ptr Word8 -> Ptr CULLong ->
--                         Ptr CChar -> CULLong -> Ptr CChar -> IO CInt
