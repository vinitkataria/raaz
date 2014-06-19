{- |

Elliptic curve Diffie - Hellman Key Exchange.

-}
{-# LANGUAGE TypeFamilies #-}
module Raaz.ECDH.Exchange
       ( generateParamsCurve25519
       , calculateSecretCurve25519
       , generateParamsNISTp192
       , calculateSecretNISTp192
       ) where


import Raaz.Core.Primitives.Cipher

import Raaz.ECDH.Types
import Raaz.Random

import Raaz.KeyExchange

import Data.Bits

-- | Generates the private number x (1 < x < q) and public number scalar multiple of basepoint.
generateParamsCurve25519 :: ( StreamGadget g)
                          => RandomSource g
                          -> Curve25519 Word256
                          -> IO (PrivateNum Word256, PublicNum Word256)
generateParamsCurve25519 rsrc curve@(Curve25519 _ _ _ _ gx'' _ q'') = do
  xrandom <- genBetween rsrc (2::Word256) (q'' - 1)
  let byte0  = (248 `shiftL` 224)
      byte31 = 127
      temp1 = (byte31 .&. (xrandom .&. byte0))
      privnum = (temp1 .|. 64)
  return (PrivateNum privnum, PublicNum $ (getAffineX (affinify curve (pMult curve privnum (PointProj (gx'') undefined undefined)))))

-- | Calculate the shared secret.
calculateSecretCurve25519 :: Curve25519 Word256
                          -> PrivateNum Word256
                          -> PublicNum Word256
                          -> SharedSecret Word256
calculateSecretCurve25519 curve (PrivateNum priv) (PublicNum e) =
  SharedSecret $ (getAffineX (affinify curve (pMult curve priv (PointProj (e::Word256) undefined undefined))))

-- | Generates the private number x (1 < x < q) and public number scalar multiple of basepoint.
generateParamsNISTp192 :: (StreamGadget g)
                        => RandomSource g
                        -> NISTp192 Word192
                        -> IO (PrivateNum Word192, PublicNum Word192)
generateParamsNISTp192 rsrc curve@(NISTp192 _ _ _ _ gx'' gy'' q'') = do
  privnum <- genBetween rsrc (2::Word192) (q'' - 1)
  return (PrivateNum privnum, PublicNum $ (getAffineX (pMult curve privnum (PointAffine gx'' gy''))))

-- | Calculate the shared secret.
calculateSecretNISTp192 :: NISTp192 Word192
                        -> PrivateNum Word192
                        -> PublicNum Word192
                        -> SharedSecret Word192
calculateSecretNISTp192 curve (PrivateNum priv) (PublicNum e) =
--to be looked at later
  SharedSecret $ (getAffineX (pMult curve priv (PointAffine (e::Word192) undefined)))