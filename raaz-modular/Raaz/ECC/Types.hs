{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE CPP                        #-}
module Raaz.ECC.Types
       ( PublicKey (..)
       , PrivateKey (..)
       , keySize, xorByteString
       , ECC(..)
       , ECCGadget(..)
       ) where

import Control.Applicative
import Data.Bits
import Data.ByteString       as BS
import Data.Monoid
import Foreign.Ptr           (castPtr)
import Foreign.Storable      (Storable(..), sizeOf)

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Parse.Unsafe
import Raaz.Core.Write.Unsafe
import Raaz.Core.Serialize
import Raaz.Core.Types

import Raaz.Number.Internals
import Raaz.Number.Util

-- | ECC Public Key
data PublicKey w = PublicKey
                   { pubd     :: w           -- ^ d
                   , pubGx    :: w           -- ^ Gx
                   , pubGy    :: w           -- ^ Gy
                   } deriving Show

-- | ECC Private Key
data PrivateKey w = PrivateKey
                    { privd   :: w           -- ^ d
                    } deriving Show

instance Eq w => Eq (PublicKey w) where
  (==) (PublicKey d1 gx1 gy1) (PublicKey d2 gx2 gy2) = (d1   ==   d2) `safeAnd`
                                                       (gx1  ==  gx2) `safeAnd`
                                                       (gy1  ==  gy2)
instance Eq w => Eq (PrivateKey w) where
  (==) (PrivateKey d1) (PrivateKey d2) = (d1   ==   d2)

instance Storable w => Storable (PublicKey w) where
  sizeOf _     = 3 * sizeOf (undefined :: w)
  alignment _  = alignment (undefined :: w)
  peek ptr     = runParser (castPtr ptr) $ PublicKey <$> parseStorable
                                                     <*> parseStorable
                                                     <*> parseStorable
  poke ptr k   = runWrite (castPtr ptr) $  writeStorable (pubd  k)
                                        <> writeStorable (pubGx k)
                                        <> writeStorable (pubGy k)

instance Storable w => Storable (PrivateKey w) where
  sizeOf _     = 1 * sizeOf (undefined :: w)
  alignment _  = alignment (undefined :: w)
  peek ptr     = runParser (castPtr ptr) $ PrivateKey <$> parseStorable
  poke ptr k   = runWrite (castPtr ptr) $  writeStorable (privd  k)

-- | Stores individual words in Big Endian.
instance (Num w, Storable w, Integral w) => EndianStore (PublicKey w) where
  load cptr    = runParser cptr $ PublicKey <$> parseWordBE <*> parseWordBE
  store cptr k = runWrite cptr  $  writeWordBE (pubd k)
                                <> writeWordBE (pubGx k)
                                <> writeWordBE (pubGy k)

instance (Num w, Storable w, Integral w) => CryptoSerialize (PublicKey w)


-- | ECC type. @k@ is key size (eg `Word1024`), @h@ is the underlying
-- hash used and @mode@ is mode of operation
-- (eg `SignMode`, `EncryptMode`)
#if UseKinds
data ECC k h (mode :: Mode) = ECC deriving (Show, Eq)
#else
data ECC k h mode = RSA deriving (Show, Eq)
{-# DEPRECATED ECC
   "Kind restriction on n and mode will be added from GHC 7.6 onwards" #-}
#endif


-- | ECC Gadget
-- | RSA Gadget
#if UseKinds
data ECCGadget k g (m :: Mode) =
#else
data ECCGadget k g m =
#endif
     ECCGadget (ECCMem k m) g


-- | This is a helper type family to unify Auth, Verify, Encrypt and
-- Decrypt Gadgets in the same ECCGadget. It changes the type of
-- Gadget's memory depending on Mode.
#if UseKinds
type family ECCMem k (m :: Mode) :: *
#else
type family ECCMem k m :: *
#endif

type instance ECCMem k SignMode = CryptoCell (PrivateKey k)
type instance ECCMem k VerifyMode = (CryptoCell (PublicKey k), CryptoCell k)

type instance ECCMem k EncryptMode = CryptoCell (PublicKey k)
type instance ECCMem k DecryptMode = CryptoCell (PrivateKey k)

keySize :: Storable w => k w -> BYTES Int
keySize = BYTES . sizeOf . getW
  where getW :: k w -> w
        getW = undefined
{-# SPECIALIZE keySize :: PublicKey Word1024 -> BYTES Int #-}
{-# SPECIALIZE keySize :: PublicKey Word2048 -> BYTES Int #-}
{-# SPECIALIZE keySize :: PublicKey Word4096 -> BYTES Int #-}
{-# SPECIALIZE keySize :: PrivateKey Word1024 -> BYTES Int #-}
{-# SPECIALIZE keySize :: PrivateKey Word2048 -> BYTES Int #-}
{-# SPECIALIZE keySize :: PrivateKey Word4096 -> BYTES Int #-}


-- | Xor two bytestring. If bytestrings are of different length then
-- the larger one is truncated to the length of shorter one.
xorByteString :: ByteString -> ByteString -> ByteString
xorByteString o1 o2 = BS.pack $ BS.zipWith xor o1 o2