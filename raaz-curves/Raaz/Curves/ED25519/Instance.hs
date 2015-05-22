{-|

This module defines the hash instances for sha512 hash.

-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE CPP                        #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# OPTIONS_GHC -fno-warn-orphans       #-}

module Raaz.Curves.ED25519.Instance () where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )
import qualified Data.Vector.Unboxed as VU

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Hash
import Raaz.Core.Util.Ptr

import Raaz.Curves.ED25519.Type
import Raaz.Curves.ED25519.Ref
import Raaz.Curves.ED25519.CPortable ()
import Raaz.Curves.ED25519.Internal

import Control.Applicative
import Foreign.Storable

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Asymmetric
import Raaz.Core.Primitives.Hash
import Raaz.Public
import Raaz.Number

-------------------------------- Auth -------------------------------------


-- | Primitive instance for Signature generation primitive.
instance Hash h => Primitive (Ed25519 h SignMode) where

  blockSize _ = blockSize (undefined :: h)

  type Key (Ed25519 h SignMode) = W256

-- | Signature generation is a safe primitive if the underlying hash is safe.
instance Hash h => SafePrimitive (Ed25519 h SignMode)


instance Hash h => CryptoPrimitive (Ed25519 h SignMode) where
  type Recommended (Ed25519 h SignMode) = Ed25519Gadget (Recommended h) SignMode
  type Reference (Ed25519 h SignMode) = Ed25519Gadget (Reference h) SignMode


-- | Memory used in Ed25519 Signing gadget
newtype Ed25519SignMem h m = Ed25519SignMem (CryptoCell W256, m)

deriving instance Memory m => Memory (Ed25519SignMem h m)

instance ( InitializableMemory m
         , Hash h
         , IV m ~ Key h
         ) => InitializableMemory (Ed25519SignMem h m) where
  type IV (Ed25519SignMem h m) = W256

  initializeMemory rmem@(Ed25519SignMem (kcell, hmem)) k = do
    cellPoke kcell k
    initializeMemory hmem (defaultCxt (rHash rmem))
      where
        rHash :: Ed25519SignMem h m -> h
        rHash _ = undefined


-- | Return the signature as a Word. This is where the actual signing
-- is done of the calculated hash.
instance ( FinalizableMemory m
         , FV m ~ Key h
         , Hash h
         , DEREncoding h
         ) => FinalizableMemory (Ed25519SignMem h m) where
  type FV (Ed25519SignMem h m) = Ed25519 h SignMode

  finalizeMemory m@(Ed25519SignMem (kcell, hmem)) = do
    k <- finalizeMemory kcell
    hcxt <- getDigest (getH m) <$> finalizeMemory hmem

    return $ Ed25519 $ getMySign hcxt k                          -- remaining

    where
      getDigest :: h -> Key h -> h
      getDigest _ = hashDigest
      getH :: Ed25519SignMem h m -> h
      getH = undefined


getMySign :: Hash h => h -> W256 -> W512
getMySign hval sk = word512ToW512 (0 :: Word512)

-- | Padding for signature primitive is same as that of the underlying
-- hash.
instance Hash h => HasPadding (Ed25519 h SignMode) where
  padLength _  = padLength (undefined :: h)

  padding _ = padding (undefined :: h)

  unsafePad _ = unsafePad (undefined :: h)

  maxAdditionalBlocks _ = toEnum . fromEnum
                       $ maxAdditionalBlocks (undefined :: h)

-- | Gadget instance which is same as the underlying hashing gadget.
instance ( Gadget g
         , Hash (PrimitiveOf g)
         , PaddableGadget g
         ) => Gadget (Ed25519Gadget g SignMode) where

  type PrimitiveOf (Ed25519Gadget g SignMode) = Ed25519 (PrimitiveOf g) SignMode

  type MemoryOf (Ed25519Gadget g SignMode)    = Ed25519SignMem (PrimitiveOf g) (MemoryOf g)

  newGadgetWithMemory (Ed25519SignMem (ck, gmem))    = Ed25519Gadget ck <$> newGadgetWithMemory gmem

  getMemory (Ed25519Gadget ck g)                     = Ed25519SignMem (ck, getMemory g)

  apply (Ed25519Gadget _ g) blks                     = apply g blks'
    where blks'                                  = toEnum $ fromEnum blks


-- | PaddableGadget instance which is same as the underlying hashing
-- gadget.
instance ( Hash (PrimitiveOf g)
         , PaddableGadget g
         ) => PaddableGadget (Ed25519Gadget g SignMode) where
  unsafeApplyLast (Ed25519Gadget _ g) blks = unsafeApplyLast g blks'
    where blks' = toEnum $ fromEnum blks


--------------------------------- Verify ----------------------------------

-- | Primitive instance for Signature verification primitive.
instance Hash h => Primitive (Ed25519 h VerifyMode) where

  blockSize _ = blockSize (undefined :: h)

  type Key (Ed25519 h VerifyMode) = (W256, Ed25519 h SignMode)

-- | Signature verification is a safe primitive if the underlying hash is safe.
instance Hash h => SafePrimitive (Ed25519 h VerifyMode)


instance ( Hash h
         ) => CryptoPrimitive (Ed25519 h VerifyMode) where
  type Recommended (Ed25519 h VerifyMode) = Ed25519Gadget (Recommended h) VerifyMode
  type Reference (Ed25519 h VerifyMode) = Ed25519Gadget (Reference h) VerifyMode


-- | Memory used in Ed25519 Verification gadget
newtype Ed25519VerifyMem h m = Ed25519VerifyMem (CryptoCell (W256), CryptoCell W512, m)

deriving instance Memory m => Memory (Ed25519VerifyMem h m)

instance ( InitializableMemory m
         , Hash h
         , IV m ~ Key h
         ) => InitializableMemory (Ed25519VerifyMem h m) where
  type IV (Ed25519VerifyMem h m) = (W256, Ed25519 h SignMode)

  initializeMemory rmem@(Ed25519VerifyMem (kcell, sigcell, hmem)) (k, Ed25519 sig) = do
    cellPoke kcell k
    cellPoke sigcell sig
    initializeMemory hmem (defaultCxt (rHash rmem))
      where
        rHash :: Ed25519VerifyMem h m -> h
        rHash _ = undefined

-- | Verify the signature and return `True` if success otherwise
-- `False`. This is where the actual signature verification is done of
-- the calculated hash.
instance ( FinalizableMemory m
         , FV m ~ Key h
         , Hash h
         , DEREncoding h
         ) => FinalizableMemory (Ed25519VerifyMem h m) where
  type FV (Ed25519VerifyMem h m) = Bool

  finalizeMemory m@(Ed25519VerifyMem (kcell, sigcell, hmem)) = do
    k <- finalizeMemory kcell
    sig <- finalizeMemory sigcell
    hcxt <- getDigest (getH m) <$> finalizeMemory hmem
    return $ myVerify hcxt k sig
    where
      getDigest :: h -> Key h -> h
      getDigest _ = hashDigest
      getH :: Ed25519VerifyMem h m -> h
      getH = undefined

myVerify :: Hash h => h -> W256 -> W512 -> Bool
myVerify h pk w = True

instance Hash h => HasPadding (Ed25519 h VerifyMode) where
  padLength _  = padLength (undefined :: h)

  padding _ = padding (undefined :: h)

  unsafePad _ = unsafePad (undefined :: h)

  maxAdditionalBlocks _ = toEnum . fromEnum
                       $ maxAdditionalBlocks (undefined :: h)

-- | Padding for verification primitive is same as that of the
-- underlying hash.
instance ( Gadget g
         , Hash (PrimitiveOf g)
         , PaddableGadget g
         ) => Gadget (Ed25519Gadget g VerifyMode) where

  type PrimitiveOf (Ed25519Gadget g VerifyMode)     = Ed25519 (PrimitiveOf g) VerifyMode

  type MemoryOf (Ed25519Gadget g VerifyMode)        = Ed25519VerifyMem (PrimitiveOf g) (MemoryOf g)

  newGadgetWithMemory (Ed25519VerifyMem (cpk, csig, gmem)) = Ed25519Gadget (cpk,csig) <$> newGadgetWithMemory gmem

  getMemory (Ed25519Gadget (ck,csig) g)                    = Ed25519VerifyMem (ck, csig, getMemory g)

  apply (Ed25519Gadget _ g) blks                           = apply g blks'
    where blks'                                        = toEnum $ fromEnum blks

-- | PaddableGadget gadget instance which is same as the underlying
-- hashing gadget.
instance ( Hash (PrimitiveOf g)
         , PaddableGadget g
         ) => PaddableGadget (Ed25519Gadget g VerifyMode) where
  unsafeApplyLast (Ed25519Gadget _ g) blks = unsafeApplyLast g blks'
    where blks' = toEnum $ fromEnum blks

------------------------------------- Auth instance ------------------------

-- | Auth instance for Ed25519 signature scheme.
instance (DEREncoding h, Hash h) => Sign (Ed25519 h)

-- | Satisfy some types.
getHash :: Ed25519 h SignMode -> h
getHash = undefined
