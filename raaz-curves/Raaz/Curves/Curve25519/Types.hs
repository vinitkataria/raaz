{- |

Types for D.J. Bernstein's Curve25519.

-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FunctionalDependencies #-}
module Raaz.ECDH.Types
       ( Curve25519(..)
       , ECclass(..)
       , ECPrime(..)
       , PointAffine(..)
       , PointProj(..)
       , getAffineX
       , getAffineY
       , modinv
       , module Raaz.Number.Internals
       ) where

import Raaz.Number.Internals
import Data.Bits
import Raaz.Number.Util

data PointAffine w = PointAffine { x :: w, y :: w} deriving Show
data PointProj w   = PointProj { x' :: w, y' :: w, z' :: w} deriving Show

instance Eq w => Eq (PointAffine w) where
  (PointAffine x y) == (PointAffine x' y') = (x == x' && y == y')
  _ == _                                   = False

instance Eq w => Eq (PointProj w) where
  (PointProj x y z) == (PointProj x' y' z') = (x == x' && y == y' && z == z')
  _ == _                                    = False

class ECclass ec w | ec -> w where
  type Point ec :: *
  pAdd       :: ec -> Point ec -> Point ec -> Point ec
  pDouble    :: ec -> Point ec -> Point ec
  pMult      :: ec -> w -> Point ec -> Point ec
  affinify   :: ec -> PointProj w -> PointAffine w
  projectify :: PointAffine w -> PointProj w

getAffineX :: PointAffine w -> w
getAffineX (PointAffine x'' _) = x''

getAffineY :: PointAffine w -> w
getAffineY (PointAffine _ y''') = y'''

egcd :: (Integral w) => w -> w -> (w,w,w)
egcd 0 s = (s,0,1)
egcd r s = let (g, s1, r1) = egcd (s `mod` r) r
           in (g, r1 - (s `div` r) * s1, s1)

modinv :: (Integral w) => w -> w -> w
modinv a m = let (g, r, _) = egcd a m
             in if g == 1
                then r `mod` m
                else undefined

-- Montgomery curve equation : by^2 = x^3 + ax^2 + x, p = prime, g = basepoint
-- for curve25519 A = 486662, w = Word256, prime p = 2^255 - 19, basepoint Gx = 9
data Curve25519 w = Curve25519 deriving (Eq, Show)

curve25519L  = 256
curve25519P  = 57896044618658097711785492504343953926634992332820282019728792003956564819949 -- (2^255 - 19)
curve25519A  = 486662
curve25519B  = 1
curve25519Gx = 9
curve25519Q  = 7237005577332262213973186563042994240857116359379907606001950938285454250989 -- (2^252 + 27742317777372353535851937790883648493)

instance ECclass (Curve25519 Word256) Word256 where
  type Point (Curve25519 Word256)   = PointProj Word256
  pDouble curve (PointProj x1 _ z1) = (PointProj x2 undefined z2)
    where
      p  = getPp curve
      a  = getPa curve
      m  = ((x1 + z1) * (x1 + z1)) `mod` p
      n  = ((x1 - z1) * (x1 - z1)) `mod` p
      r  = (m - n) `mod` p
      s  = (m + (((((a-2) `div` 4) :: Word256) * r) `mod` p)) `mod` p
      x2 = (m * n) `mod` p
      z2 = (r * s) `mod` p

  pAdd curve point1@(PointProj x1 _ z1) point2@(PointProj x2 _ z2)
    | (point1 == point2) = pDouble curve point1
    | otherwise          = (PointProj x3 undefined z3)
    where
      p  = getPp curve
      gx = getPgx curve
      m  = ((x1 + z1) * (x2 - z2)) `mod` p
      n  = ((x1 - z1) * (x2 + z2)) `mod` p
      x3 = ((m + n) * (m + n)) `mod` p
      e  = ((m - n) * (m - n)) `mod` p
      z3 = (e * gx) `mod` p

  pMult curve k' point@(PointProj x4 _ z4) = montgom (nbits - 2) point (pDouble curve point)
    where
      k                 = k' `mod` ((getPp curve) - 1)
      nbits             = fromEnum $ numberOfBits k
      montgom (-1) r0 _ = r0
      montgom bitnum r0 r1
       | testBit k bitnum = let r1r1 = pDouble curve r1
                              in montgom (bitnum-1) r0r1 r1r1
       | otherwise        = let r0r0 = pDouble curve r0
                              in montgom (bitnum-1) r0r0 r0r1
       where r0r1 = pAdd curve r0 r1

  affinify curve (PointProj px py pz) = (PointAffine ax ay)
    where
--    zinv  = powModuloSlowSafe pz (prime - 2) prime
      prime = getPp curve
      zinv  = pz `modinv` prime
      ax    = (px * zinv) `mod` prime
      ay    = (py * zinv) `mod` prime
      powModuloSlowSafe g k m = operate nbits 1 g
        where
          nbits          = fromEnum $ numberOfBits k
          operate 0 r0 _ = r0
          operate bitnum r0 r1
           | testBit k (bitnum-1) = let r1r1 = r1*r1 `mod` m
                                      in operate (bitnum-1) r0r1 r1r1
           | otherwise            = let r0r0 = r0*r0 `mod` m
                                      in operate (bitnum-1) r0r0 r0r1
           where r0r1 = r0*r1 `mod` m

  projectify (PointAffine ax ay) = (PointProj ax ay 1)
