{- |

This module implements gadget instances for ECC signing and
verification.

-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE KindSignatures       #-}
{-# LANGUAGE CPP                  #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Raaz.ECC.Signature.Instances where

import Control.Applicative
import Data.Default
import Foreign.Storable

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Asymmetric
import Raaz.Core.Primitives.Hash

import Raaz.Number.Modular
import Raaz.Public
import Raaz.ECC.Types
import Raaz.ECC.Signature.Primitives

-------------------------------- Auth -------------------------------------


-- | Private Key is used for signature generation.
type instance Key (ECC k h SignMode) = PrivateKey k

-- | Primitive instance for Signature generation primitive.
instance Hash h => Primitive (ECC k h SignMode) where

  blockSize _ = blockSize (undefined :: h)

  data Cxt (ECC k h SignMode) = Auth (PrivateKey k) (Cxt h)

-- | Signature generation is a safe primitive if the underlying hash is safe.
instance Hash h => SafePrimitive (ECC k h SignMode)


-- | Return the signature as a Word. This is where the actual signing
-- is done of the calculated hash.
instance ( DEREncoding h
         , Modular k
         , Num k
         , Storable k
         , Eq k
         , Ord k
         , Hash h
         ) => Digestible (ECC k h SignMode) where

  type Digest (ECC k h SignMode) = k

  toDigest (Auth k hcxt) = rsaPKCSSign (toDigest hcxt) k


-- | Padding for signature primitive is same as that of the underlying
-- hash.
instance Hash h => HasPadding (ECC k h SignMode) where
  padLength _  = padLength (undefined :: h)

  padding _ = padding (undefined :: h)

  unsafePad _ = unsafePad (undefined :: h)

  maxAdditionalBlocks _ = toEnum . fromEnum
                       $ maxAdditionalBlocks (undefined :: h)

-- | Gadget instance which is same as the underlying hashing gadget.
instance ( Gadget g
         , Hash (PrimitiveOf g)
         , PaddableGadget g
         , Storable k
         ) => Gadget (ECCGadget k g SignMode) where

  type PrimitiveOf (ECCGadget k g SignMode) = ECC k (PrimitiveOf g) SignMode

  type MemoryOf (ECCGadget k g SignMode) = (CryptoCell (PrivateKey k), MemoryOf g)

  newGadgetWithMemory (ck, gmem) = ECCGadget ck <$> newGadgetWithMemory gmem

  initialize (ECCGadget ck g) (Auth priv hcxt) =  cellStore ck priv
                                                   >> initialize g hcxt

  finalize (ECCGadget ck g) = Auth <$> cellLoad ck <*> finalize g

  apply (ECCGadget _ g) blks = apply g blks'
    where blks' = toEnum $ fromEnum blks


-- | PaddableGadget instance which is same as the underlying hashing
-- gadget.
instance ( Hash (PrimitiveOf g)
         , PaddableGadget g
         , Storable k
         ) => PaddableGadget (ECCGadget k g SignMode) where
  unsafeApplyLast (ECCGadget _ g) blks = unsafeApplyLast g blks'
    where blks' = toEnum $ fromEnum blks

--------------------------------- Verify ----------------------------------


-- | Public Key is use for signature verification
type instance Key (ECC k h VerifyMode) = PublicKey k

-- | Primitive instance for Signature verification primitive.
instance Hash h => Primitive (ECC k h VerifyMode) where

  blockSize _ = blockSize (undefined :: h)

  data Cxt (ECC k h VerifyMode) = Verify (PublicKey k) k (Cxt h)

-- | Signature verification is a safe primitive if the underlying hash is safe.
instance Hash h => SafePrimitive (ECC k h VerifyMode)


-- | Verify the signature and return `True` if success otherwise
-- `False`. This is where the actual signature verification is done of
-- the calculated hash.
instance ( DEREncoding h
         , Modular k
         , Num k
         , Storable k
         , Eq k
         , Ord k
         , Hash h
         ) => Digestible (ECC k h VerifyMode) where

  type Digest (ECC k h VerifyMode) = Bool

  toDigest (Verify k sig hcxt) = rsaVerify (toDigest hcxt) k sig

instance Hash h => HasPadding (ECC k h VerifyMode) where
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
         , Storable k
         ) => Gadget (ECCGadget k g VerifyMode) where

  type PrimitiveOf (ECCGadget k g VerifyMode) = ECC k (PrimitiveOf g) VerifyMode

  type MemoryOf (ECCGadget k g VerifyMode) = ((CryptoCell (PublicKey k), CryptoCell k), MemoryOf g)

  newGadgetWithMemory (cell, gmem) = ECCGadget cell <$> newGadgetWithMemory gmem

  initialize (ECCGadget (ck, csig) g) (Verify pub sig hcxt) =  cellStore ck pub
                                                                >> cellStore csig sig
                                                                >> initialize g hcxt

  finalize (ECCGadget (ck, csig) g) = Verify <$> cellLoad ck <*> cellLoad csig<*> finalize g

  apply (ECCGadget _ g) blks = apply g blks'
    where blks' = toEnum $ fromEnum blks

-- | PaddableGadget gadget instance which is same as the underlying
-- hashing gadget.
instance ( Hash (PrimitiveOf g)
         , PaddableGadget g
         , Storable k
         ) => PaddableGadget (ECCGadget k g VerifyMode) where
  unsafeApplyLast (ECCGadget _ g) blks = unsafeApplyLast g blks'
    where blks' = toEnum $ fromEnum blks

------------------------------------- Auth instance ------------------------

-- | Auth instance for ECC signature scheme.
instance ( Modular k
         , Hash h
         , Storable k
         , Num k
         , Integral k
         , DEREncoding h
         ) => Sign (ECC k h) where
  signCxt priv = Auth priv def
  verifyCxt pub sig = Verify pub sig def
