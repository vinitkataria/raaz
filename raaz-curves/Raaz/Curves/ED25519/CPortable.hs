{- |

This module gives the recommended implementation of the DH functions
over Curve25519. This uses the ed25519 implementation from
https://github.com/agl/curve25519-donna/.

-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE CPP                      #-}
{-# CFILES raaz/curves/cportable/ed25519/ed25519.c #-}

#include "MachDeps.h"

module Raaz.Curves.ED25519.CPortable
        ( createKeypair
        , createKeypairGivenRandom
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


foreign import ccall unsafe "ed25519_sign_keypair"
  c_crypto_sign_keypair :: CryptoPtr -> CryptoPtr -> IO CInt

foreign import ccall unsafe "ed25519_sign_keypair_given_random"
  c_crypto_sign_keypair_given_random :: CryptoPtr -> CryptoPtr -> IO CInt

foreign import ccall unsafe "ed25519_sign"
  c_crypto_sign :: Ptr Word8 -> Ptr CULLong ->
                   Ptr CChar -> CULLong -> Ptr CChar -> IO CULLong

foreign import ccall unsafe "ed25519_sign_open"
  c_crypto_sign_open :: Ptr Word8 -> Ptr CULLong ->
                        Ptr CChar -> CULLong -> Ptr CChar -> IO CInt

-- #if WORD_SIZE_IN_BITS < 64
-- foreign import ccall unsafe
--   "curve25519-donna.c raaz_curve25519_donna_portable"
--    c_curve25519_donna :: CryptoPtr -> CryptoPtr -> CryptoPtr -> IO CInt
-- #else
-- foreign import ccall unsafe
--     "curve25519-donna-c64.c raaz_curve25519_donna_c64"
--      c_curve25519_donna :: CryptoPtr -> CryptoPtr -> CryptoPtr -> IO CInt
-- #endif


-- | Randomly generate a public and private key for doing
-- authenticated signing and verification.
-- createKeypair :: IO (PublicKey, SecretKey)
-- createKeypair = do
--   pk <- SI.mallocByteString cryptoSignPUBLICKEYBYTES
--   sk <- SI.mallocByteString cryptoSignSECRETKEYBYTES

--   _ <- withForeignPtr pk $ \ppk -> do
--     _ <- withForeignPtr sk $ \psk -> do
--       _ <- c_crypto_sign_keypair ppk psk
--       return ()
--     return ()

--   return (PublicKey $ SI.fromForeignPtr pk 0 cryptoSignPUBLICKEYBYTES,
--           SecretKey $ SI.fromForeignPtr sk 0 cryptoSignSECRETKEYBYTES)

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


-- | Given a random number, generates the secret and publictoken tuple
-- params25519Reco :: P25519 -> IO (Secret25519, PublicToken25519)
-- params25519Reco randomnum = do
--   let basenum   = integerToP25519 curve25519Gx
--       secretnum = randomnum
--       szBytes   = byteSize (undefined :: P25519)
--       size      = sizeOf (undefined :: P25519)
--       totalSize = szBytes * 3
--   allocaBuffer totalSize $ \ ptr -> do
--     store (ptr `plusPtr` size) secretnum
--     store (ptr `plusPtr` (2*size)) basenum
--     void $ c_curve25519_donna ptr (ptr `plusPtr` size) (ptr `plusPtr` (2*size))
--     pubkey <- load ptr
--     secret <- load (ptr `plusPtr` size)
--     return (Secret25519 secret, PublicToken25519 pubkey)

cryptoSignSECRETKEYBYTES :: Int
cryptoSignSECRETKEYBYTES = 64

cryptoSignPUBLICKEYBYTES :: Int
cryptoSignPUBLICKEYBYTES = 32

cryptoSignBYTES :: Int
cryptoSignBYTES = 64
