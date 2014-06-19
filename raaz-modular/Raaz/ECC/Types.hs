{-# LANGUAGE MultiParamTypeClasses #-} 
{-# LANGUAGE FlexibleInstances #-} 
{-# LANGUAGE TypeFamilies #-} 
{-# LANGUAGE FunctionalDependencies #-} 
module Raaz.ECC.Types
       ( Curve25519(..)
       , ECclass(..)
       , ECPrime(..)
       , ECBinary(..)
       , PointAffine(..)
       , PointProj(..)
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
  pMult    :: ec -> w -> Point ec

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
 
-- data ECurve w = ECPrime
                -- { l  :: Int
                -- , p  :: w
                -- , a  :: w
                -- , b  :: w
                -- , gx :: w
                -- , gy :: w
                -- , q  :: w
                -- }
              -- | ECBinary
                -- { l  :: Int  
                -- , f  :: w    -- reduction poly
                -- , a  :: w
                -- , b  :: w
                -- , gx :: w
                -- , gy :: w
                -- , q  :: w
                -- }  

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
                    }

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

  pMult curve@(Curve25519 _ _ _ _ gx3 _ _) k = montgom nbits (PointProj 1 undefined 0) (PointProj gx3 undefined 1)
    where
      nbits = fromEnum $ numberOfBits k
      montgom 0 r0 _ = r0
      montgom bitnum r0 r1
       | testBit k (bitnum-1) = let r1r1 = pDouble curve r1
                                in montgom (bitnum-1) r0r1 r1r1
       | otherwise = let r0r0 = pDouble curve r0
                     in montgom (bitnum-1) r0r0 r0r1
       where r0r1 = pAdd curve r0 r1
