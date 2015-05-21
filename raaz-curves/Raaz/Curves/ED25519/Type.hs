{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}

module Raaz.Curves.ED25519.Type
       ( Sign(..)
       ) where

import           Control.Applicative ( (<$>) )
import qualified Data.Vector.Unboxed                  as VU
import           Data.Word
import           Data.Typeable       ( Typeable     )
import           Foreign.Ptr         ( castPtr      )
import           Foreign.Storable    ( Storable(..) )

import           Raaz.Core.Classes
import           Raaz.Core.Parse.Applicative
import           Raaz.Core.Primitives
import           Raaz.Core.Types
import           Raaz.Core.Write
import           Raaz.Curves.ED25519.Util

----------------------------- Sign -------------------------------------------

-- | The Sha512 hash value. Used in implementation of Sha384 as well.
newtype Sign = Sign (VU.Vector (BE Word64)) deriving ( Show, Typeable )

-- | Timing independent equality testing for sha512
instance Eq Sign where
 (==) (Sign g) (Sign h) = oftenCorrectEqVector g h

instance HasName Sign

instance Storable Sign where
  sizeOf    _ = 8 * sizeOf (undefined :: (BE Word64))
  alignment _ = alignment  (undefined :: (BE Word64))

  peek = unsafeRunParser sha512parse . castPtr
    where sha512parse = Sign <$> unsafeParseStorableVector 8

  poke ptr (Sign v) = unsafeWrite writeSign cptr
    where writeSign = writeStorableVector v
          cptr = castPtr ptr

instance EndianStore Sign where
  load = unsafeRunParser $ Sign <$> unsafeParseVector 8

  store cptr (Sign v) = unsafeWrite writeSign cptr
    where writeSign = writeVector v

instance Primitive Sign where
  blockSize _ = BYTES 128
  {-# INLINE blockSize #-}
  type Key Sign = Sign

instance SafePrimitive Sign

instance HasPadding Sign where
  maxAdditionalBlocks _ = 1
  padLength = shaPadLength 16
  padding   = shaPadding   16
