{-|

This module exposes the `EC25519` curve constructor.

-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FunctionalDependencies #-}

module Raaz.Curves.EC25519.Types
       ( EC25519
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

import Raaz.Curves.P25519.Internal
import Data.Bits ()
import Foreign.Storable

----------------------------- EC25519 -------------------------------------------
-- Montgomery curve equation : by^2 = x^3 + ax^2 + x, p = prime, g = basepoint
-- for EC25519 A = 486662, C = A/4, w = P25519, prime p = 2^255 - 19, basepoint Gx = 9
data EC25519 w = EC25519 deriving (Eq, Show)

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

data PointAffine w = PointAffine { ax :: w} deriving Show
data PointProj w   = PointProj { px :: w, pz :: w} deriving Show

instance Eq w => Eq (PointAffine w) where
  (PointAffine x) == (PointAffine x') = (x == x')

instance Eq w => Eq (PointProj w) where
  (PointProj x z) == (PointProj x' z') = (x == x' && z == z')

pInfinity :: PointProj P25519
pInfinity = PointProj 1 0

-- | Secret
newtype Secret25519 w = Secret25519 w
                    deriving (Show, Eq, Ord, Num, Integral, Storable, Real, Enum)

-- | Public Token
newtype PublicToken25519 w = PublicToken25519 w
                    deriving (Show, Eq, Ord, Num, Integral, Storable, Real, Enum)

-- | Shared Secret
newtype SharedSecret25519 w = SharedSecret25519 w
                       deriving (Show, Eq, Ord, Num, Integral, Storable, Real, Enum)
