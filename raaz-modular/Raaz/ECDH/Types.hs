{- |

Types for Elliptic Curve Diffie Hellman key exchange.

-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FunctionalDependencies #-}
module Raaz.ECDH.Types
       ( Curve25519(..)
       , ECclass(..)
       , ECPrime(..)
       , ECBinary(..)
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

data PointAffine w = PointAffine { x :: w, y :: w} deriving (Show, Eq)
data PointProj w = PointProj   { x' :: w, y' :: w, z' :: w} deriving (Show, Eq)

class ECclass ec w | ec -> w where
  type Point ec :: *
  pAdd     :: ec -> Point ec -> Point ec -> Point ec
  pDouble  :: ec -> Point ec -> Point ec
  pMult    :: ec -> w -> Point ec -> Point ec
  affinify :: ec -> PointProj w -> PointAffine w
  projectify :: PointAffine w -> PointProj w

class ECPrime c where
  type WordTypePrime c :: *
  getPl  :: c -> Int
  getPp  :: c -> WordTypePrime c
  getPa  :: c -> WordTypePrime c
  getPb  :: c -> WordTypePrime c
  getPgx :: c -> WordTypePrime c
  getPgy :: c -> WordTypePrime c
  getPq  :: c -> WordTypePrime c

class ECBinary c where
  type WordTypeBinary c :: *
  getBl  :: c -> Int
  getBp  :: c -> WordTypeBinary c
  getBa  :: c -> WordTypeBinary c
  getBb  :: c -> WordTypeBinary c
  getBgx :: c -> WordTypeBinary c
  getBgy :: c -> WordTypeBinary c
  getBq  :: c -> WordTypeBinary c

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
data Curve25519 w = Curve25519
                    { l  :: Int
                    , a  :: w
                    , b  :: w
                    , p  :: w
                    , gx :: w
                    , gy :: w
                    , q  :: w
                    } deriving (Eq, Show)

instance ECPrime (Curve25519 Word256) where
  type WordTypePrime (Curve25519 Word256) = Word256
  getPl _  = 256
  getPp _  = 57896044618658097711785492504343953926634992332820282019728792003956564819949 -- (2^255 - 19)
  getPa _  = 486662
  getPb _  = 1
  getPgx _ = 9
  getPgy _ = undefined
  getPq _  = 7237005577332262213973186563042994240857116359379907606001950938285454250989 -- (2^252 + 27742317777372353535851937790883648493)

instance ECclass (Curve25519 Word256) Word256 where
  type Point (Curve25519 Word256) = PointProj Word256
  pDouble (Curve25519 _ p1 a1 _ _ _ _) (PointProj x1 _ z1) = (PointProj x2 undefined z2)
    where
      m = ((x1 + z1) * (x1 + z1)) `mod` p1
      n = ((x1 - z1) * (x1 - z1)) `mod` p1
      r = (m - n) `mod` p1
      s = (m + (((((a1-2) `div` 4) :: Word256) * r) `mod` p1)) `mod` p1
      x2 = (m * n) `mod` p1
      z2 = (r * s) `mod` p1

  pAdd (Curve25519 _ p2 _ _ gx2 _ _) (PointProj x1 _ z1) (PointProj x2 _ z2) = (PointProj x3 undefined z3)
    where
      m = ((x1 + z1) * (x2 - z2)) `mod` p2
      n = ((x1 - z1) * (x2 + z2)) `mod` p2
      x3 = ((m + n) * (m + n)) `mod` p2
      e = ((m - n) * (m - n)) `mod` p2
      z3 = (e * gx2) `mod` p2

  pMult curve k (PointProj x4 _ z4) = montgom nbits (PointProj 1 undefined 0) (PointProj x4 undefined z4)
    where
      nbits = fromEnum $ numberOfBits k
      montgom 0 r0 _ = r0
      montgom bitnum r0 r1
       | testBit k (bitnum-1) = let r1r1 = pDouble curve r1
                                in montgom (bitnum-1) r0r1 r1r1
       | otherwise = let r0r0 = pDouble curve r0
                     in montgom (bitnum-1) r0r0 r0r1
       where r0r1 = pAdd curve r0 r1

  affinify (Curve25519 _ prime _ _ _ _ _) (PointProj px py pz) = (PointAffine ax ay)
    where
--    zinv = powModuloSlowSafe pz (prime - 2) prime
      zinv = pz `modinv` prime
      ax = (px * zinv) `mod` prime
      ay = (py * zinv) `mod` prime
      powModuloSlowSafe g k m = operate nbits 1 g
        where
          nbits = fromEnum $ numberOfBits k
          operate 0 r0 _ = r0
          operate bitnum r0 r1
           | testBit k (bitnum-1) = let r1r1 = r1*r1 `mod` m
                                    in operate (bitnum-1) r0r1 r1r1
           | otherwise = let r0r0 = r0*r0 `mod` m
                         in operate (bitnum-1) r0r0 r0r1
           where r0r1 = r0*r1 `mod` m

  projectify (PointAffine ax ay) = (PointProj ax ay 1)
