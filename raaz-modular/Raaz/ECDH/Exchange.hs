{- |

Elliptic curve Diffie - Hellman Key Exchange.

-}
{-# LANGUAGE TypeFamilies #-}
module Raaz.ECDH.Exchange
       ( generateParamsCurve25519
       , calculateSecretCurve25519
       ) where


import Raaz.Core.Primitives.Cipher

import Raaz.ECDH.Types
import Raaz.Random

import Raaz.KeyExchange

-- | Generates the private number x (1 < x < q) and public number e = g^x mod p.
generateParamsCurve25519 :: ( StreamGadget g
							)
			 => RandomSource g
		  	 -> Curve25519 Word256
			 -> IO (PrivateNum Word256, PublicNum Word256)
generateParamsCurve25519 rsrc curve@(Curve25519 _ _ _ _ gx'' _ q'') = do
  xrandom <- genBetween rsrc (2::Word256) (q'' - 1)
  return (PrivateNum xrandom, PublicNum $ (getAffineX (affinify curve (pMult curve xrandom (PointProj (gx'') undefined undefined)))))

-- | Calculate the shared secret.
calculateSecretCurve25519 :: Curve25519 Word256
    					  -> PrivateNum Word256
						  -> PublicNum Word256
						  -> SharedSecret Word256
calculateSecretCurve25519 curve (PrivateNum priv) (PublicNum e) =
  SharedSecret $ (getAffineX (affinify curve (pMult curve priv (PointProj (e::Word256) undefined undefined))))
