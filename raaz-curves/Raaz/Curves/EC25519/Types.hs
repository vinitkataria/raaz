{-|

This module exposes the `EC25519` curve constructor.

-}
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
       ) where

import Raaz.Curves.P25519.Internal
import Raaz.Number.Internals
import Data.Bits ()

----------------------------- EC25519 -------------------------------------------
-- Montgomery curve equation : by^2 = x^3 + ax^2 + x, p = prime, g = basepoint
-- for EC25519 A = 486662, C = A/4, w = P25519, prime p = 2^255 - 19, basepoint Gx = 9
data EC25519 w = EC25519 deriving (Eq, Show)

curve25519L :: Integer
curve25519L  = 256

curve25519P :: Word256
curve25519P  = 57896044618658097711785492504343953926634992332820282019728792003956564819949 -- (2^255 - 19)

curve25519A :: P25519
curve25519A  = P25519 486662

curve25519B :: P25519
curve25519B  = P25519 1

curve25519C :: P25519
curve25519C  = P25519 121665

curve25519Gx :: P25519
curve25519Gx  = P25519 9

curve25519Q :: Word256
curve25519Q  = 57896044618658097711785492504343953926856930875039260848015607506283634007912 -- 8 * (2^252 + 27742317777372353535851937790883648493)

data PointAffine w = PointAffine { ax :: w, ay :: w} deriving Show
data PointProj w   = PointProj { px :: w, py :: w, pz :: w} deriving Show

instance Eq w => Eq (PointAffine w) where
  (PointAffine x y) == (PointAffine x' y') = (x == x' && y == y')

instance Eq w => Eq (PointProj w) where
  (PointProj x y z) == (PointProj x' y' z') = (x == x' && y == y' && z == z')

pInfinity :: PointProj P25519
pInfinity = PointProj 1 undefined 0

--class ECclass ec where
--  data Point ec  :: *
--  pAdd       :: Point ec -> Point ec -> Point ec
--  pDouble    :: Point ec -> Point ec
--  pMult      :: Bits a   => a -> Point ec -> Point ec
--  affinify   :: Point ec -> Point ec
--  projectify :: Point ec -> Point ec
