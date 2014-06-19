{-# LANGUAGE TypeFamilies #-}
module Raaz.ECC.Signature.Primitives
       ( eccPKCSSign
       , eccPKCSVerify
       ) where

import           Control.Exception        ( throw )
import           Foreign.Storable
import qualified Data.ByteString           as BS

import           Raaz.Core.Types
import qualified Raaz.Core.Util.ByteString as BU

import           Raaz.Public
import           Raaz.ECC.Exception
import           Raaz.ECC.Types
import           Raaz.Number.Internals
import           Raaz.Number

-- | ECC signature generation primitive
eccsp1 :: ( Num w
          , Modular w
          , Eq w
          , Ord w
          )
       => PrivateKey w
       -> w
       -> w
eccsp1 privK m | (m < 0) || (m >= n) =
                  throw MessageRepresentativeOutOfRange
               | otherwise = powModuloSafe m d n
  where
    n = privN privK
    d = privD privK

-- | ECC signature verification primitive
eccvp1 :: ( Num w
          , Modular w
          , Eq w
          , Ord w
          )
       => PublicKey w
       -> w
       -> w
eccvp1 (PublicKey n e) s
  | (s < 0) || (s >= n) = throw SignatureRepresentativeOutOfRange
  | otherwise = powModulo s e n


-- Note: Doesn't handle the case when message is larger than the data
-- hash function can handle. It is intended to output message to long
-- error.

-- | EMSA-PKCS1-v1_5 deterministic encoding routine
emsaPKCSEncode :: ( DEREncoding h
                  , Modular w
                  , Storable w
                  , Num w
                  , Eq w
                  , Ord w
                  )
               => h  -- ^ Hashed Message
               -> w  -- ^ Encoded Message
emsaPKCSEncode m = em
 where
   -- Step 1 and 2
   emLen = BYTES $ sizeOf em
   t = derEncode m
   tLen = BU.length t
   -- Step 4
   psLen = emLen - tLen - 3
   bps = BS.replicate (fromIntegral psLen) 0xff
   -- Step 5
   em = os2wp $ BS.concat [ BS.singleton 0x00
                          , BS.singleton 0x01
                          , bps
                          , BS.singleton 0x00
                          , t]

-- | ECC Signature generature routine.
eccSign :: ( DEREncoding h
               , Num w
               , Modular w
               , Storable w
               , Eq w
               , Ord w
               )
            => h            -- ^ Hashed Message
            -> PrivateKey w -- ^ Private Key
            -> w            -- ^ Signature
eccSign m privK = eccsp1 privK $ emsaPKCSEncode m

-- | ECC Signature verification routine.
eccVerify :: ( DEREncoding h
                 , Num w
                 , Modular w
                 , Storable w
                 , Eq w
                 , Ord w
                 )
              => h             -- ^ Hashed Message
              -> PublicKey w   -- ^ Private Key
              -> w             -- ^ Signature to be verified
              -> Bool          -- ^ valid (True) or Invalid (False)
eccVerify m pubK sig = eccvp1 pubK sig == emsaPKCSEncode m
