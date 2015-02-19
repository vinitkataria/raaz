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
import Raaz.Core.DH
import System.IO.Unsafe (unsafePerformIO)

newtype Param = Param Integer deriving Show

data Param2 = Param2 Integer Integer deriving Show

instance Arbitrary Param where
  arbitrary = do
    let q = curve25519Q
    w <- choose (2, q) :: Gen Integer
    return $ Param w

instance Arbitrary Param2 where
  arbitrary = do
    let q = curve25519Q
    w1 <- choose (2, q) :: Gen Integer
    w2 <- choose (2, q) :: Gen Integer
    return $ Param2 w1 w2

prop_genparams25519 :: Param -> Bool
prop_genparams25519 (Param random) = priv1 == priv2 && pub1 == pub2
  where secret = generateSecretEC25519 random
        (priv1, pub1) = (secret, publicToken (undefined :: P25519) secret)
        (priv2, pub2) = unsafePerformIO $ cGenerateParamsEC25519 random

prop_gensharedsecret25519 :: Param2 -> Bool
prop_gensharedsecret25519 (Param2 random1 random2) = priv1 == priv2 && pub1 == pub2 && sharedSecret1 == sharedSecret2
  where secret1 = generateSecretEC25519 random1
        (priv1, pub1) = (secret1, publicToken (undefined :: P25519) secret1)
        (priv2, pub2) = unsafePerformIO $ cGenerateParamsEC25519 random1
        secret2 = generateSecretEC25519 random2
        sharedSecret1 = sharedSecret (undefined :: P25519) secret2 pub1
        sharedSecret2 = unsafePerformIO $ cCalculateSecretEC25519 (Secret25519 (integerToP25519                                                                                                                                                                                                                                                                                                                                                              random2)) pub2

tests = [ testProperty "Generate Params Test" prop_genparams25519
        , testProperty "Generate SharedSecret Test" prop_gensharedsecret25519
        ]
