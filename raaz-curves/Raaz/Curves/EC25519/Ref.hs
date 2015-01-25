{-|

This module gives the reference implementation of the curve EC25519.

-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}

module Raaz.Curves.EC25519.Ref
       ( pDouble
       , pAdd
       , pMult
       , affinify
       , projectify
       , getEntropyP25519
       , getPseudoRandomP25519
       , generateSecretEC25519
       , publicToken
       , sharedSecret
       , Secret25519
       , PublicToken25519
       ) where

import Raaz.Curves.EC25519.Types
import Raaz.Curves.P25519.Internal
import Raaz.Core.Random
--import Raaz.Core.DH

import Data.Bits

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

getEntropyP25519 :: IO P25519
getEntropyP25519 = do
  src <- openEntropy
  gen src

getPseudoRandomP25519 :: IO P25519
getPseudoRandomP25519 = do
  src <- openPseudoRandom
  gen src

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

-- | Given a random number, generates the private number x (1 < x < q)
generateSecretEC25519 :: P25519 -> Secret25519 P25519
generateSecretEC25519 (P25519 randomNum) = (Secret25519 $ P25519 (getSecretFromRandom randomNum))

--instance DH P25519 where
--  type Secret P25519 = Secret25519 P25519
--  type PublicToken P25519 = PublicToken25519 P25519
--  type SharedSecret P25519 = SharedSecret25519 P25519

publicToken _ (Secret25519 secret) = PublicToken25519 pubToken
  where
    publicPoint = pMult secret (PointProj curve25519Gx 1)
    pubToken = ax (affinify publicPoint)

sharedSecret _ (Secret25519 secret) (PublicToken25519 pubToken) = SharedSecret25519 sharednum
  where
    sharedPoint = pMult secret (PointProj pubToken 1)
    sharednum   = ax (affinify sharedPoint)
