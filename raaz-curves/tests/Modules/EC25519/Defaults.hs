{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE Rank2Types #-}

module Modules.EC25519.Defaults where

import Control.Applicative
import Data.Bits
import Data.Word
import Test.Framework                       ( Test, testGroup )
import Test.Framework.Providers.QuickCheck2 ( testProperty    )
import Test.QuickCheck
import Test.QuickCheck.Property as P

import Raaz.Curves.EC25519.Types
import Raaz.Curves.EC25519.Ref
import Raaz.Curves.EC25519.CPortable
import Raaz.Curves.P25519.Internal
import System.IO.Unsafe (unsafePerformIO)

newtype Param = Param Integer deriving Show

instance Arbitrary Param where
  arbitrary = do
    let q = curve25519Q
    w <- choose (5, 5) :: Gen Integer
    return $ Param w

prop_genparams25519 :: Param -> Bool
prop_genparams25519 (Param random) = priv1 == priv2 && pub1 == pub2
  where (priv1, pub1) = generateParamsEC25519Random (P25519 random)
        (priv2, pub2) = unsafePerformIO $ cGenerateParamsEC25519 (P25519 random)

tests = [ testProperty "GenerateParams Test" prop_genparams25519 ]
