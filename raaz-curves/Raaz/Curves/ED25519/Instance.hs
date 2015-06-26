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
{-# LANGUAGE UndecidableInstances       #-}
{-# OPTIONS_GHC -fno-warn-orphans       #-}

module Raaz.Curves.ED25519.Instance (
 -- myVerify, getMySign
                                     ) where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )
import qualified Data.Vector.Unboxed as VU

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Hash
import Raaz.Core.Util.Ptr

import Raaz.Curves.ED25519.Type
-- import Raaz.Curves.ED25519.Ref
-- import Raaz.Curves.ED25519.CPortable ()
import Raaz.Curves.ED25519.Internal

import Control.Applicative
import Foreign.Storable

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Asymmetric
import Raaz.Core.Primitives.Hash
import Raaz.Public
import Raaz.Number
import Raaz.Hash.Sha512
import Raaz.Core.Types
import Data.Bits
import qualified Data.ByteString                      as B

-------------------------------- Auth -------------------------------------


-- | Primitive instance for Signature generation primitive.
instance Primitive h => Primitive (Ed25519Sign h) where

  blockSize                = blockSize . gethash

  type Key (Ed25519Sign h) = SecretKey

-- | Signature generation is a safe primitive if the underlying hash is safe.
instance SafePrimitive h => SafePrimitive (Ed25519Sign h)


instance Hash h => CryptoPrimitive (Ed25519Sign h) where
  type Recommended (Ed25519Sign h) = EdSignGadget (Recommended h)
  type Reference (Ed25519Sign h) = EdSignGadget (Reference h)


-- | Memory used in Ed25519 Signing gadget
-- newtype Ed25519SignMem h m = Ed25519SignMem (CryptoCell SecretKey, m)

-- deriving instance Memory m => Memory (Ed25519SignMem h m)

instance (Gadget g, Hash (PrimitiveOf g)) => Memory (EdSignGadget g) where

  memoryAlloc = EdSignGadget <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  underlyingPtr (EdSignGadget kcell _ _ _ _)  = underlyingPtr kcell

instance ( Hash (PrimitiveOf g)
         , Gadget g
         , IV g ~ Key (PrimitiveOf g)
         ) => InitializableMemory (EdSignGadget g) where
  type IV (EdSignGadget g) = SecretKey

  initializeMemory rmem@(EdSignGadget kcell g1 g2 g3 hbuf) k = do

    cellPoke kcell k

    -- Compute first hash of secretkey
    initializeMemory g1 startCxt
    -- hmacSetGadget 0x36 key ig hbuf

    -- Compute second hash
    initializeMemory g2 startCxt
    -- hmacSetGadget 0x5c key og hbuf

    -- Compute third hash
    initializeMemory g3 startCxt
    -- hmacSetGadget 0x36 key ig hbuf
    where
      startCxt = defaultKey $ primitiveOf g1

-- | Return the signature as a Word. This is where the actual signing
-- is done of the calculated hash.
instance ( FV g ~ Key (PrimitiveOf g)
         , Gadget g
         , Hash (PrimitiveOf g)
         ) => FinalizableMemory (EdSignGadget g) where
  type FV (EdSignGadget g) = Ed25519Sign W512

  finalizeMemory m@(EdSignGadget kcell g1 g2 g3 hbuf) = do
    sk <- finalizeMemory kcell
    -- hcxt <- getDigest (getH m) <$> finalizeMemory hmem
    -- let pkw' = pKey $ getPublicKey sk
    --     skw' = sKey sk
    --     skw = w256ToWord256 skw'
    --     pkw = w256ToWord256 pkw'
    --     hashval = gethash sk
    --     hashi = fromIntegral hashval
    --     a = getA hashi
    --     m = unsafeFromHex msg
    --     upperh = (fromIntegral $ (reverseWord hashval) .&. ((1 `shiftL` 256)-1)) :: Word256
    --     rBS = B.append (wordToByteString upperh) m
    return $ Ed25519Sign (word512ToW512 (123 :: Word512))
    -- return $ Ed25519 $ getMySign hcxt sk                          -- remaining
    -- where
    --   getDigest :: h -> Key h -> h
    --   getDigest _ = hashDigest
    --   getH :: Ed25519SignMem h m -> h
    --   getH = undefined


-- getMySign :: Hash h => h -> SecretKey -> W512
-- getMySign hval sk = word512ToW512 (0 :: Word512)

-- | Padding for signature primitive is same as that of the underlying
-- hash.
-- instance Hash h => HasPadding (Ed25519Sign h) where
--   padLength _  = padLength (undefined :: h)

--   padding _ = padding (undefined :: h)

--   unsafePad _ = unsafePad (undefined :: h)

--   maxAdditionalBlocks _ = toEnum . fromEnum
--                        $ maxAdditionalBlocks (undefined :: h)

instance HasPadding h => HasPadding (Ed25519Sign h) where
  padLength hmc bits = padLength h bits'
    where h     = gethash hmc
          bits' = bits + inBits (blocksOf 1 hmc)

  padding hmc bits = padding h bits'
    where h     = gethash hmc
          bits' = bits + inBits (blocksOf 1 hmc)

  unsafePad hmc bits = unsafePad h bits'
    where h     = gethash hmc
          bits' = bits + inBits (blocksOf 1 hmc)

  maxAdditionalBlocks  = toEnum . fromEnum
                       . maxAdditionalBlocks
                       . gethash

-- | Gadget instance which is same as the underlying hashing gadget.
instance ( Gadget g, prim ~ PrimitiveOf g
         , Hash prim
         , IV g ~ Key prim
         , FV g ~ Key prim
         ) => Gadget (EdSignGadget g) where

  type PrimitiveOf (EdSignGadget g) = Ed25519Sign (PrimitiveOf g)

  recommendedBlocks = toEnum . fromEnum . recommendedBlocks . gethashGadget

  apply (EdSignGadget _ g _ _ _) blks = apply g blks'
    where blks' = toEnum $ fromEnum blks


-- | PaddableGadget instance which is same as the underlying hashing
-- gadget.
instance ( PaddableGadget g
         , Hash (PrimitiveOf g)
         , FinalizableMemory g
         , IV g ~ Key (PrimitiveOf g)
         , FV g ~ Key (PrimitiveOf g)
         ) => PaddableGadget (EdSignGadget g) where
  unsafeApplyLast (EdSignGadget _ g _ _ _) blks = unsafeApplyLast g blks'
    where blks' = toEnum $ fromEnum blks

-- | Generate Signature.
-- edsign' :: ( Sign p
--          , FinalizableMemory (MemoryOf g)
--          , FV (MemoryOf g) ~ prim
--          , prim ~ p SignMode
--          , PaddableGadget g
--          , prim ~ PrimitiveOf g
--          )
--       => g             -- ^ Type of Gadget
--       -> Key prim      -- ^ Key
--       -> B.ByteString  -- ^ Message
--       -> prim
-- edsign' g key src = unsafePerformIO $ withGadget key $ go g
--   where go :: ( Sign prim
--               , PaddableGadget g1
--               , FinalizableMemory (MemoryOf g1)
--               , prim SignMode ~ PrimitiveOf g1
--               )
--            => g1 -> g1 -> IO (FV (MemoryOf g1))
--         go _ gad =  do
--           transformGadget gad src
--           finalize gad

-- -- | Generate signature using recommended gadget.
-- edsign :: ( Sign p
--         , g ~ Recommended prim
--         , FinalizableMemory (MemoryOf g)
--         , FV (MemoryOf g) ~ prim
--         , prim ~ p SignMode
--         , PaddableGadget g
--         , CryptoPrimitive prim
--         )
--         => Key prim      -- ^ Key
--         -> B.ByteString  -- ^ Message
--         -> prim
-- edsign key src = sig
--   where
--     sig = edsign' (recommended sig) key src
--     recommended :: prim -> Recommended prim
--     recommended _ = undefined



-- --------------------------------- Verify ----------------------------------

-- -- | Primitive instance for Signature verification primitive.
-- instance Hash h => Primitive (Ed25519Verify h) where

--   blockSize _ = blockSize (undefined :: h)

--   type Key (Ed25519Verify h) = (PublicKey, Ed25519Sign h)

-- -- | Signature verification is a safe primitive if the underlying hash is safe.
-- instance Hash h => SafePrimitive (Ed25519Verify h)


-- instance ( Hash h
--          ) => CryptoPrimitive (Ed25519Verify h) where
--   type Recommended (Ed25519Verify h) = Ed25519Gadget (Recommended h) VerifyMode
--   type Reference (Ed25519Verify h) = Ed25519Gadget (Reference h) VerifyMode


-- -- | Memory used in Ed25519 Verification gadget
-- newtype Ed25519VerifyMem h m = Ed25519VerifyMem (CryptoCell (PublicKey), CryptoCell W512, m)

-- deriving instance Memory m => Memory (Ed25519VerifyMem h m)

-- instance ( InitializableMemory m
--          , Hash h
--          , IV m ~ Key h
--          ) => InitializableMemory (Ed25519VerifyMem h m) where
--   type IV (Ed25519VerifyMem h m) = (PublicKey, Ed25519Sign h)

--   initializeMemory rmem@(Ed25519VerifyMem (kcell, sigcell, hmem)) (k, Ed25519 sig) = do
--     cellPoke kcell k
--     cellPoke sigcell sig
--     initializeMemory hmem (defaultCxt (rHash rmem))
--       where
--         rHash :: Ed25519VerifyMem h m -> h
--         rHash _ = undefined

-- -- | Verify the signature and return `True` if success otherwise
-- -- `False`. This is where the actual signature verification is done of
-- -- the calculated hash.
-- instance ( FinalizableMemory m
--          , FV m ~ Key h
--          , Hash h
--          , DEREncoding h
--          ) => FinalizableMemory (Ed25519VerifyMem h m) where
--   type FV (Ed25519VerifyMem h m) = Bool

--   finalizeMemory m@(Ed25519VerifyMem (kcell, sigcell, hmem)) = do
--     k <- finalizeMemory kcell
--     sig <- finalizeMemory sigcell
--     hcxt <- getDigest (getH m) <$> finalizeMemory hmem
--     return $ myVerify hcxt k sig
--     where
--       getDigest :: h -> Key h -> h
--       getDigest _ = hashDigest
--       getH :: Ed25519VerifyMem h m -> h
--       getH = undefined

-- myVerify :: Hash h => h -> PublicKey -> W512 -> Bool
-- myVerify h pk w = True

-- instance Hash h => HasPadding (Ed25519Verify h) where
--   padLength _  = padLength (undefined :: h)

--   padding _ = padding (undefined :: h)

--   unsafePad _ = unsafePad (undefined :: h)

--   maxAdditionalBlocks _ = toEnum . fromEnum
--                        $ maxAdditionalBlocks (undefined :: h)

-- -- | Padding for verification primitive is same as that of the
-- -- underlying hash.
-- instance ( Gadget g
--          , Hash (PrimitiveOf g)
--          , PaddableGadget g
--          ) => Gadget (EdVerifyGadget g) where

--   type PrimitiveOf (EdVerifyGadget g)     = Ed25519 (PrimitiveOf g) VerifyMode

--   type MemoryOf (EdVerifyGadget g)        = Ed25519VerifyMem (PrimitiveOf g) (MemoryOf g)

--   newGadgetWithMemory (Ed25519VerifyMem (cpk, csig, gmem)) = Ed25519Gadget (cpk,csig) <$> newGadgetWithMemory gmem

--   getMemory (Ed25519Gadget (ck,csig) g)                    = Ed25519VerifyMem (ck, csig, getMemory g)

--   apply (Ed25519Gadget _ g) blks                           = apply g blks'
--     where blks'                                        = toEnum $ fromEnum blks

-- -- | PaddableGadget gadget instance which is same as the underlying
-- -- hashing gadget.
-- instance ( Hash (PrimitiveOf g)
--          , PaddableGadget g
--          ) => PaddableGadget (EdVerifyGadget g) where
--   unsafeApplyLast (Ed25519Gadget _ g) blks = unsafeApplyLast g blks'
--     where blks' = toEnum $ fromEnum blks

------------------------------------- Auth instance ------------------------

-- | Auth instance for Ed25519 signature scheme.
-- instance (DEREncoding h, Hash h) => Sign (Ed25519 h)

-- | Satisfy some types.
gethash :: Ed25519Sign h -> h
gethash = undefined

gethashGadget :: EdSignGadget g -> g
gethashGadget (EdSignGadget _ g _ _ _) = g
