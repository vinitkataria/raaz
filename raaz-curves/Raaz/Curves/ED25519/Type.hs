{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE CPP                        #-}
module Raaz.Curves.ED25519.Type
       ( Ed25519Sign(..)
       , Ed25519Verify(..)
       , EdSignGadget(..)
       , EdVerifyGadget(..)
       , SecretKey(..)
       , PublicKey(..)
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
import           Raaz.Core.Primitives.Hash
import           Raaz.Core.Types
import           Raaz.Core.Write
import           Raaz.Core.Memory
-- import           Raaz.Curves.ED25519.Util
import           Raaz.Curves.ED25519.Internal

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
import Raaz.Core.Types

import Raaz.Curves.ED25519.Internal
-- import Raaz.Number.Internals
-- import Raaz.Number.Util

-- | Ed25519 type. @k@ is key size (eg `Word512`), @h@ is the underlying
-- hash used and @mode@ is mode of operation (eg `SignMode`,
-- `EncryptMode`)
-- #if UseKinds
-- data Ed25519 h (mode :: Mode) = Ed25519 W512 deriving (Show, Eq)
--   -- deriving (Show, Eq, Num, Integral, Storable, Bits, Real, Ord, Enum)
-- #else
-- data Ed25519 h mode = Ed25519 W512 deriving (Show, Eq)
  -- deriving (Show, Eq, Num, Integral, Storable, Bits, Real, Ord, Enum)
-- # DEPRECATED Ed25519
--    "Kind restriction on n and mode will be added from GHC 7.6 onwards" #
-- #endif

-- | Ed25519 Gadget
-- #if UseKinds
-- data Ed25519Gadget g (m :: Mode) =
-- #else
-- data Ed25519Gadget g m =
-- #endif
--      Ed25519Gadget (Ed25519Mem m)
--                    g -- first hash of secret key
--                    g -- second hash along with message
--                    g -- third hash along with message
--                    (HashMemoryBuf (PrimitiveOf g))
--                       -- buffer used to take repeated hashes

data Ed25519Sign h = Ed25519Sign W512 deriving (Show, Eq)
data Ed25519Verify h = Ed25519Verify W512 deriving (Show, Eq)

data EdSignGadget g = EdSignGadget (MemoryCell (SecretKey))
                                   g -- first hash of secret key
                                   g -- second hash along with message
                                   g -- third hash along with message
                                   (HashMemoryBuf (PrimitiveOf g))
                                      -- buffer used to take repeated hashes

data EdVerifyGadget g = EdVerifyGadget (MemoryCell (PublicKey), MemoryCell W512)
                                       g -- for the hash




-- | This is a helper type family to unify Auth, Verify, Encrypt and
-- Decrypt Gadgets in the same Ed25519Gadget. It changes the type of
-- Gadget's memory depending on Mode.
-- #if UseKinds
-- type family Ed25519Mem (m :: Mode) :: *
-- #else
-- type family Ed25519Mem m :: *
-- #endif

-- type instance Ed25519Mem SignMode = MemoryCell (SecretKey)
-- type instance Ed25519Mem VerifyMode = (MemoryCell (PublicKey), MemoryCell W512)

-- type instance Ed25519Mem EncryptMode = MemoryCell (PublicKey)
-- type instance Ed25519Mem DecryptMode = MemoryCell (SecretKey)

keySize :: Storable w => k w -> BYTES Int
keySize = BYTES . sizeOf . getW
  where getW :: k w -> w
        getW = undefined

-- | Xor two bytestring. If bytestrings are of different length then
-- the larger one is truncated to the length of shorter one.
xorByteString :: ByteString -> ByteString -> ByteString
xorByteString o1 o2 = BS.pack $ BS.zipWith xor o1 o2

-- | Mask Function
type MGF = ByteString -> BYTES Int -> ByteString
