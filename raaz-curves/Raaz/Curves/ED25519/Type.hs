{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE CPP                        #-}
module Raaz.Curves.ED25519.Type
       ( Ed25519(..)
       , Ed25519Gadget(..)
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
import           Raaz.Core.Types
import           Raaz.Core.Write
import           Raaz.Curves.ED25519.Util
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
#if UseKinds
data Ed25519 h (mode :: Mode) = Ed25519 W512 deriving (Show, Eq)
  -- deriving (Show, Eq, Num, Integral, Storable, Bits, Real, Ord, Enum)
#else
data Ed25519 h mode = Ed25519 W512 deriving (Show, Eq)
  -- deriving (Show, Eq, Num, Integral, Storable, Bits, Real, Ord, Enum)
{-# DEPRECATED Ed25519
   "Kind restriction on n and mode will be added from GHC 7.6 onwards" #-}
#endif

-- | Ed25519 Gadget
#if UseKinds
data Ed25519Gadget g (m :: Mode) =
#else
data Ed25519Gadget g m =
#endif
     Ed25519Gadget (Ed25519Mem m) g


-- | This is a helper type family to unify Auth, Verify, Encrypt and
-- Decrypt Gadgets in the same Ed25519Gadget. It changes the type of
-- Gadget's memory depending on Mode.
#if UseKinds
type family Ed25519Mem (m :: Mode) :: *
#else
type family Ed25519Mem m :: *
#endif

type instance Ed25519Mem SignMode = CryptoCell (SecretKey)
type instance Ed25519Mem VerifyMode = (CryptoCell (PublicKey), CryptoCell W512)

type instance Ed25519Mem EncryptMode = CryptoCell (PublicKey)
type instance Ed25519Mem DecryptMode = CryptoCell (SecretKey)

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
