{- |

Type for the prime P25519.

-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE CPP                        #-}
module Raaz.Curves.P25519.Internal
      ( P25519(..)
      , pDouble
      , pAdd
      , pMult
      , affinify
      , projectify
      , getEntropyP25519
      , getPseudoRandomP25519
      , generateSecretEC25519
      , publicToken
      , sharedSecret
      , curve25519L
      , curve25519A
      , curve25519B
      , curve25519C
      , curve25519P
      , curve25519Gx
      , curve25519Q
      , pInfinity
      , PointAffine(..)
      , PointProj(..)
      , Secret25519(..)
      , PublicToken25519(..)
      , SharedSecret25519(..)
      ) where

import Control.Monad
import Data.Bits
import Data.Typeable
import Foreign.Marshal (allocaBytes)
import Foreign.Ptr (castPtr)
import Foreign.Storable (peek, Storable)
import System.IO (hGetBuf)
import Raaz.Number
import Raaz.Core.DH
import Raaz.Core.Random
--import Raaz.Curves.EC25519.Types


----------------------------- EC25519 -------------------------------------------
-- Montgomery curve equation : by^2 = x^3 + ax^2 + x, p = prime, g = basepoint
-- for EC25519 A = 486662, C = A/4, w = P25519, prime p = 2^255 - 19, basepoint Gx = 9

curve25519L :: Integer
curve25519L  = 256

curve25519P :: Integer
curve25519P  = 57896044618658097711785492504343953926634992332820282019728792003956564819949 -- (2^255 - 19)

curve25519A :: P25519
curve25519A  = P25519 486662

curve25519B :: P25519
curve25519B  = P25519 1

curve25519C :: P25519
curve25519C  = P25519 121665

curve25519Gx :: P25519
curve25519Gx  = P25519 9

curve25519Q :: Integer
curve25519Q  = 7237005577332262213973186563042994240857116359379907606001950938285454250989 -- (2^252 + 27742317777372353535851937790883648493)

data PointAffine w = PointAffine { ax :: w } deriving Show
data PointProj w   = PointProj { px :: w, pz :: w } deriving Show

instance Eq w => Eq (PointAffine w) where
  (PointAffine x) == (PointAffine x') = (x == x')

instance Eq w => Eq (PointProj w) where
  (PointProj x z) == (PointProj x' z') = (x == x' && z == z')

pInfinity :: PointProj P25519
pInfinity = PointProj 1 0



-- | Modulo Prime 2^255 - 19
newtype P25519 = P25519 Integer
                  deriving (Integral, Show, Ord, Real, Modular, Typeable, Eq)

-- | Reduced Word256 to module prime p25519
narrowP25519 :: Integer -> Integer
narrowP25519 w = w `mod` p25519
{-# INLINE narrowP25519 #-}

p25519 :: Integer
p25519 = (1 `shiftL` 255) - 19
{-# INLINE p25519 #-}

instance Num P25519 where
  (+) (P25519 a) (P25519 b) = P25519 $ narrowP25519 (a + b)
  (-) (P25519 a) (P25519 b) = P25519 $ narrowP25519 (a - b)
  (*) (P25519 a) (P25519 b) = P25519 $ narrowP25519 (a * b)
  abs x                     = x
  signum 0                  = 0
  signum _                  = 1
  fromInteger               = P25519 . narrowP25519

instance Bounded P25519 where
  minBound = 0
  maxBound = P25519 $ p25519 - 1

instance Enum P25519 where
  succ x | x /= maxBound = x + 1
         | otherwise     = error "succ: P25519"
  pred x | x /= minBound = x - 1
         | otherwise     = error "pred: P25519"
  toEnum                 = P25519 . toEnum
  fromEnum (P25519 a)    = fromEnum a

instance Random P25519 where
  gen (RandomDev handle) = allocaBytes 32 $ \buf -> do
  void $ hGetBuf handle buf 32
  word256 <- ((peek (castPtr buf)) :: IO Word256)
  return $ P25519 ((fromIntegral word256) :: Integer)

instance DH P25519 where
  type Secret P25519 = Secret25519 P25519
  type PublicToken P25519 = PublicToken25519 P25519
  type SharedSecret P25519 = SharedSecret25519 P25519

  publicToken _ (Secret25519 secret) = PublicToken25519 pubToken
    where
      publicPoint = pMult secret (PointProj curve25519Gx 1)
      pubToken = ax (affinify publicPoint)

  sharedSecret _ (Secret25519 secret) (PublicToken25519 pubToken) = SharedSecret25519 sharednum
    where
      sharedPoint = pMult secret (PointProj pubToken 1)
      sharednum   = ax (affinify sharedPoint)

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
-- | Secret
newtype Secret25519 w = Secret25519 w
                    deriving (Show, Eq, Ord, Num, Integral, Storable, Real, Enum)

-- | Public Token
newtype PublicToken25519 w = PublicToken25519 w
                    deriving (Show, Eq, Ord, Num, Integral, Storable, Real, Enum)

-- | Shared Secret
newtype SharedSecret25519 w = SharedSecret25519 w
                       deriving (Show, Eq, Ord, Num, Integral, Storable, Real, Enum)


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
