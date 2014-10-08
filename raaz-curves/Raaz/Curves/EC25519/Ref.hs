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
       , generateParamsEC25519
       , generateParamsEC25519Random
       , calculateSecretEC25519
       ) where

import Raaz.Curves.EC25519.Types
import Raaz.Curves.P25519.Internal
import Raaz.Core.Primitives.Cipher
import Raaz.Random

import Data.Bits

--instance ECclass (EC25519 P25519) where
--  type Point (EC25519 P25519) = (PointProj P25519)
pDouble :: (PointProj P25519) -> (PointProj P25519)
pDouble (PointProj x1 z1) = (PointProj x2 z2)
  where
    m = (x1 + z1) * (x1 + z1)
    n = (x1 - z1) * (x1 - z1)
    r = m - n
    s = m + (curve25519C * r)
    x2 = m * n
    z2 = r * s

pAdd :: (PointProj P25519) -> (PointProj P25519) -> (PointProj P25519) -> (PointProj P25519)
pAdd basepoint point1@(PointProj x1 z1) point2@(PointProj x2 z2)
  | (point1 == point2) = pDouble point1
  | otherwise = (PointProj x3 z3)
  where
    m  = ((x1 + z1) * (x2 - z2))
    n  = ((x1 - z1) * (x2 + z2))
    x3 = ((m + n) * (m + n))
    e  = ((m - n) * (m - n))
    z3 = (e * (px basepoint))

pMult :: P25519 -> (PointProj P25519) -> (PointProj P25519)
pMult (P25519 k) basepoint = montgom nbits pInfinity basepoint
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
     where r0r1 = pAdd basepoint r0 r1

affinify :: (PointProj P25519) -> (PointAffine P25519)
affinify (PointProj x z) = (PointAffine x1)
  where
    prime = curve25519P
    zinv = powModuloSlowSafe z (prime - 2)
    x1 = (x * zinv)
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
projectify (PointAffine x) = (PointProj x 1)

getSecretFromRandom :: Integer -> Integer
getSecretFromRandom xrandom = temp6
  where
    temp1 = (((1 `shiftL` 248) - 1) `shiftL` 8) + 248
    -- temp1: (256 bit number with 248 1's followed by 248)
    temp2 = xrandom .&. temp1
    -- (Rightmost-byte `AND` with 248)
    temp3 = (127 `shiftL` 248) .|. ((1 `shiftL` 248) - 1)
    -- temp3: (256 bit number with 127 followed by 248 1's)
    temp4 = temp2 .&. temp3
    -- (Leftmost-byte `AND` with 127)
    temp5 = (64 `shiftL` 248)
    -- temp5: (256 bit number with 64 followed by 248 1's)
    temp6 = temp4 .|. temp5
    -- (Leftmost-byte `OR` with 64)

-- | Generates the private number x (1 < x < q) and public number scalar multiple of basepoint.
generateParamsEC25519 :: ( StreamGadget g )
                          => RandomSource g
                          -> IO (PrivateNum P25519, PublicNum P25519)
generateParamsEC25519 rsrc = do
  xrandom <- genBetween rsrc 2 (curve25519Q - 1)
  let privnum = P25519 (getSecretFromRandom xrandom)
      publicPoint = pMult privnum (PointProj curve25519Gx 1)
      publicnum = ax (affinify publicPoint)
  return (PrivateNum privnum, PublicNum publicnum)


-- | Given a random number, generates the private number x (1 < x < q) and public number scalar multiple of basepoint.
generateParamsEC25519Random :: P25519
                           -> (PrivateNum P25519, PublicNum P25519)
generateParamsEC25519Random (P25519 xrandom) = (PrivateNum privnum, PublicNum publicnum)
  where
    privnum = P25519 (getSecretFromRandom xrandom)
    publicPoint = pMult privnum (PointProj curve25519Gx 1)
    publicnum = ax (affinify publicPoint)

-- | Calculate the shared secret.
calculateSecretEC25519 :: PrivateNum P25519
                       -> PublicNum P25519
                       -> SharedSecret P25519
calculateSecretEC25519 (PrivateNum privnum) (PublicNum publicnum) = SharedSecret sharednum
    where (P25519 privint) = privnum
          secret = getSecretFromRandom privint
          sharedPoint = pMult (P25519 secret) (PointProj publicnum 1)
          sharednum   = ax (affinify sharedPoint)