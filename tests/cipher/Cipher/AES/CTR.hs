{-# LANGUAGE OverloadedStrings #-}
module Cipher.AES.CTR
       ( tests
       ) where


import Data.ByteString               ( ByteString, pack )
import Test.Framework                (Test              )

import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Util.ByteString

import Raaz.Cipher.AES.Type
import Raaz.Cipher.AES.CTR
import Raaz.Cipher.AES.Internal

import Cipher.AES.Defaults

-- From http://www.inconteam.com/software-development/41-encryptMode/55-aes-test-vectors
standard128Vector :: [((KEY128, STATE),ByteString,ByteString)]
standard128Vector = map (\(a,b,c,d) -> ((fromByteString a,fromByteString b),c,d))
  [ ( unsafeFromHex "2b7e151628aed2a6abf7158809cf4f3c"
    , unsafeFromHex "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    , unsafeFromHex "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    , unsafeFromHex "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee" )
  ]

standard192Vector :: [((KEY192, STATE),ByteString,ByteString)]
standard192Vector = map (\(a,b,c,d) -> ((fromByteString a,fromByteString b),c,d))
  [ ( unsafeFromHex "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    , unsafeFromHex "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    , unsafeFromHex "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    , unsafeFromHex "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050" )
  ]

standard256Vector :: [((KEY256, STATE),ByteString,ByteString)]
standard256Vector = map (\(a,b,c,d) -> ((fromByteString a,fromByteString b),c,d))
  [ ( unsafeFromHex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    , unsafeFromHex "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    , unsafeFromHex "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    , unsafeFromHex "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6" )
  ]

ctr :: AES CTR KEY128
ctr = undefined

tests :: [Test]
tests = testsDefault ctr standard128Vector standard192Vector standard256Vector