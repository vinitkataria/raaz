{-|

This module gives the reference implementation of the curve EC25519.

-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}

module Raaz.Curves.EC25519.Ref
       ( pDouble
       , pAdd
       , pMult
       , affinify
       , projectify
       ) where

import Raaz.Curves.EC25519.Types
import Raaz.Curves.P25519.Internal
import Data.Bits

--instance ECclass (EC25519 P25519) where
--  type Point (EC25519 P25519) = (PointProj P25519)
pDouble :: (PointProj P25519) -> (PointProj P25519)
pDouble (PointProj x1 _ z1) = (PointProj x2 undefined z2)
  where
    m = (x1 + z1) * (x1 + z1)
    n = (x1 - z1) * (x1 - z1)
    r = m - n
    s = m + (((((curve25519A - 2) `div` 4)) * r))
    x2 = m * n
    z2 = r * s

pAdd :: (PointProj P25519) -> (PointProj P25519) -> (PointProj P25519)
pAdd point1@(PointProj x1 _ z1) point2@(PointProj x2 _ z2)
  | (point1 == point2) = pDouble point1
  | otherwise = (PointProj x3 undefined z3)
  where
    m = ((x1 + z1) * (x2 - z2))
    n = ((x1 - z1) * (x2 + z2))
    x3 = ((m + n) * (m + n))
    e = ((m - n) * (m - n))
    z3 = (e * curve25519Gx)

pMult :: Bits k => k -> (PointProj P25519) -> (PointProj P25519)
pMult k point = montgom nbits pInfinity point
  where
    nbits = numberOfBits k 0
    numberOfBits n count
     | n == 0    = count
     | otherwise = numberOfBits (n `shiftR` 1) (count+1)
    montgom 0 r0 _ = r0
    montgom bitnum r0 r1
     | testBit k (bitnum - 1) = let r1r1 = pDouble r1
                              in montgom (bitnum-1) r0r1 r1r1
     | otherwise = let r0r0 = pDouble r0
                   in montgom (bitnum-1) r0r0 r0r1
     where r0r1 = pAdd r0 r1

affinify :: (PointProj P25519) -> (PointAffine P25519)
affinify (PointProj x y z) = (PointAffine x1 y1)
  where
    prime = curve25519P
    zinv = powModuloSlowSafe z (prime - 2)
--    zinv = pz `modinv` prime
    x1 = (x * zinv)
    y1 = (y * zinv)
    powModuloSlowSafe g k = operate nbits (1::P25519) g
      where
        nbits = numberOfBits k 0
        numberOfBits n count
         | n == 0    = count
         | otherwise = numberOfBits (n `shiftR` 1) (count+1)
        operate 0 r0 _ = r0
        operate bitnum r0 r1
         | testBit k (bitnum-1) = let r1r1 = r1*r1
                                  in operate (bitnum-1) r0r1 r1r1
         | otherwise = let r0r0 = r0*r0
                       in operate (bitnum-1) r0r0 r0r1
         where r0r1 = r0*r1

projectify :: (PointAffine P25519) -> (PointProj P25519)
projectify (PointAffine x y) = (PointProj x y 1)
