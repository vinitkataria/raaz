module Modules.RSA.Sign (tests) where

import           Data.ByteString                (ByteString)
import qualified Data.ByteString                as BS
import           Test.Framework                 (Test,testGroup)
import           Test.HUnit                     ((@=?), Assertion, assert)
import           Test.Framework.Providers.HUnit (testCase)

import           Raaz.Core.Primitives
import           Raaz.Core.Primitives.Asymmetric
import           Raaz.Core.Types
import           Raaz.Core.Test.Cipher               (shorten)
import           Raaz.Number

import           Raaz.RSA.Signature
import           Raaz.Hash.Sha1

-- https://das-labor.org/svn/microcontroller-2/arm-crypto-lib/testvectors/rsa-pkcs-1v2-1-vec/pss-vect.txt
testPubKey :: PublicKey Word1024
testPubKey = PublicKey (fromInteger $ os2ip $ BS.pack n) (fromInteger $ os2ip $ BS.pack e)
  where
    n = [0xa5,0x6e,0x4a,0x0e,0x70,0x10,0x17,0x58,0x9a,0x51,0x87,0xdc,0x7e,0xa8
        ,0x41,0xd1,0x56,0xf2,0xec,0x0e,0x36,0xad,0x52,0xa4,0x4d,0xfe,0xb1,0xe6
        ,0x1f,0x7a,0xd9,0x91,0xd8,0xc5,0x10,0x56,0xff,0xed,0xb1,0x62,0xb4,0xc0
        ,0xf2,0x83,0xa1,0x2a,0x88,0xa3,0x94,0xdf,0xf5,0x26,0xab,0x72,0x91,0xcb
        ,0xb3,0x07,0xce,0xab,0xfc,0xe0,0xb1,0xdf,0xd5,0xcd,0x95,0x08,0x09,0x6d
        ,0x5b,0x2b,0x8b,0x6d,0xf5,0xd6,0x71,0xef,0x63,0x77,0xc0,0x92,0x1c,0xb2
        ,0x3c,0x27,0x0a,0x70,0xe2,0x59,0x8e,0x6f,0xf8,0x9d,0x19,0xf1,0x05,0xac
        ,0xc2,0xd3,0xf0,0xcb,0x35,0xf2,0x92,0x80,0xe1,0x38,0x6b,0x6f,0x64,0xc4
        ,0xef,0x22,0xe1,0xe1,0xf2,0x0d,0x0c,0xe8,0xcf,0xfb,0x22,0x49,0xbd,0x9a
        ,0x21,0x37]
    e = [0x01,0x00,0x01]

testPrivKey :: PrivateKey Word1024
testPrivKey = PrivateKey (fromInteger $ os2ip $ BS.pack n)
                         (fromInteger $ os2ip $ BS.pack e)
                         (fromInteger $ os2ip $ BS.pack d)
                         (fromInteger $ os2ip $ BS.pack p)
                         (fromInteger $ os2ip $ BS.pack q)
                         (fromInteger $ os2ip $ BS.pack dp)
                         (fromInteger $ os2ip $ BS.pack dq)
                         (fromInteger $ os2ip $ BS.pack qinv)
  where
    n = [0xa5,0x6e,0x4a,0x0e,0x70,0x10,0x17,0x58,0x9a,0x51,0x87,0xdc,0x7e,0xa8
        ,0x41,0xd1,0x56,0xf2,0xec,0x0e,0x36,0xad,0x52,0xa4,0x4d,0xfe,0xb1,0xe6
        ,0x1f,0x7a,0xd9,0x91,0xd8,0xc5,0x10,0x56,0xff,0xed,0xb1,0x62,0xb4,0xc0
        ,0xf2,0x83,0xa1,0x2a,0x88,0xa3,0x94,0xdf,0xf5,0x26,0xab,0x72,0x91,0xcb
        ,0xb3,0x07,0xce,0xab,0xfc,0xe0,0xb1,0xdf,0xd5,0xcd,0x95,0x08,0x09,0x6d
        ,0x5b,0x2b,0x8b,0x6d,0xf5,0xd6,0x71,0xef,0x63,0x77,0xc0,0x92,0x1c,0xb2
        ,0x3c,0x27,0x0a,0x70,0xe2,0x59,0x8e,0x6f,0xf8,0x9d,0x19,0xf1,0x05,0xac
        ,0xc2,0xd3,0xf0,0xcb,0x35,0xf2,0x92,0x80,0xe1,0x38,0x6b,0x6f,0x64,0xc4
        ,0xef,0x22,0xe1,0xe1,0xf2,0x0d,0x0c,0xe8,0xcf,0xfb,0x22,0x49,0xbd,0x9a
        ,0x21,0x37]
    e = [0x01,0x00,0x01]
    d = [0x33,0xa5,0x04,0x2a,0x90,0xb2,0x7d,0x4f,0x54,0x51,0xca,0x9b,0xbb,0xd0
        ,0xb4,0x47,0x71,0xa1,0x01,0xaf,0x88,0x43,0x40,0xae,0xf9,0x88,0x5f,0x2a
        ,0x4b,0xbe,0x92,0xe8,0x94,0xa7,0x24,0xac,0x3c,0x56,0x8c,0x8f,0x97,0x85
        ,0x3a,0xd0,0x7c,0x02,0x66,0xc8,0xc6,0xa3,0xca,0x09,0x29,0xf1,0xe8,0xf1
        ,0x12,0x31,0x88,0x44,0x29,0xfc,0x4d,0x9a,0xe5,0x5f,0xee,0x89,0x6a,0x10
        ,0xce,0x70,0x7c,0x3e,0xd7,0xe7,0x34,0xe4,0x47,0x27,0xa3,0x95,0x74,0x50
        ,0x1a,0x53,0x26,0x83,0x10,0x9c,0x2a,0xba,0xca,0xba,0x28,0x3c,0x31,0xb4
        ,0xbd,0x2f,0x53,0xc3,0xee,0x37,0xe3,0x52,0xce,0xe3,0x4f,0x9e,0x50,0x3b
        ,0xd8,0x0c,0x06,0x22,0xad,0x79,0xc6,0xdc,0xee,0x88,0x35,0x47,0xc6,0xa3
        ,0xb3,0x25]
    p = [0xe7,0xe8,0x94,0x27,0x20,0xa8,0x77,0x51,0x72,0x73,0xa3,0x56,0x05,0x3e
        ,0xa2,0xa1,0xbc,0x0c,0x94,0xaa,0x72,0xd5,0x5c,0x6e,0x86,0x29,0x6b,0x2d
        ,0xfc,0x96,0x79,0x48,0xc0,0xa7,0x2c,0xbc,0xcc,0xa7,0xea,0xcb,0x35,0x70
        ,0x6e,0x09,0xa1,0xdf,0x55,0xa1,0x53,0x5b,0xd9,0xb3,0xcc,0x34,0x16,0x0b
        ,0x3b,0x6d,0xcd,0x3e,0xda,0x8e,0x64,0x43]
    q = [0xb6,0x9d,0xca,0x1c,0xf7,0xd4,0xd7,0xec,0x81,0xe7,0x5b,0x90,0xfc,0xca
        ,0x87,0x4a,0xbc,0xde,0x12,0x3f,0xd2,0x70,0x01,0x80,0xaa,0x90,0x47,0x9b
        ,0x6e,0x48,0xde,0x8d,0x67,0xed,0x24,0xf9,0xf1,0x9d,0x85,0xba,0x27,0x58
        ,0x74,0xf5,0x42,0xcd,0x20,0xdc,0x72,0x3e,0x69,0x63,0x36,0x4a,0x1f,0x94
        ,0x25,0x45,0x2b,0x26,0x9a,0x67,0x99,0xfd]
    dp = [0x28,0xfa,0x13,0x93,0x86,0x55,0xbe,0x1f,0x8a,0x15,0x9c,0xba,0xca,0x5a
         ,0x72,0xea,0x19,0x0c,0x30,0x08,0x9e,0x19,0xcd,0x27,0x4a,0x55,0x6f,0x36
         ,0xc4,0xf6,0xe1,0x9f,0x55,0x4b,0x34,0xc0,0x77,0x79,0x04,0x27,0xbb,0xdd
         ,0x8d,0xd3,0xed,0xe2,0x44,0x83,0x28,0xf3,0x85,0xd8,0x1b,0x30,0xe8,0xe4
         ,0x3b,0x2f,0xff,0xa0,0x27,0x86,0x19,0x79]
    dq = [0x1a,0x8b,0x38,0xf3,0x98,0xfa,0x71,0x20,0x49,0x89,0x8d,0x7f,0xb7,0x9e
         ,0xe0,0xa7,0x76,0x68,0x79,0x12,0x99,0xcd,0xfa,0x09,0xef,0xc0,0xe5,0x07
         ,0xac,0xb2,0x1e,0xd7,0x43,0x01,0xef,0x5b,0xfd,0x48,0xbe,0x45,0x5e,0xae
         ,0xb6,0xe1,0x67,0x82,0x55,0x82,0x75,0x80,0xa8,0xe4,0xe8,0xe1,0x41,0x51
         ,0xd1,0x51,0x0a,0x82,0xa3,0xf2,0xe7,0x29]
    qinv = [0x27,0x15,0x6a,0xba,0x41,0x26,0xd2,0x4a,0x81,0xf3,0xa5,0x28,0xcb,0xfb
           ,0x27,0xf5,0x68,0x86,0xf8,0x40,0xa9,0xf6,0xe8,0x6e,0x17,0xa4,0x4b,0x94
           ,0xfe,0x93,0x19,0x58,0x4b,0x8e,0x22,0xfd,0xde,0x1e,0x5a,0x2e,0x3b,0xd8
           ,0xaa,0x5b,0xa8,0xd8,0x58,0x41,0x94,0xeb,0x21,0x90,0xac,0xf8,0x32,0xb8
           ,0x47,0xf1,0x3a,0x3d,0x24,0xa7,0x9f,0x4d]

testPSSVectors :: [(ByteString,ByteString,ByteString)] -- Message,Salt,Signature
testPSSVectors = [(BS.pack m,BS.pack salt,BS.pack sig)]
  where
    m = [0xcd,0xc8,0x7d,0xa2,0x23,0xd7,0x86,0xdf,0x3b,0x45,0xe0,0xbb,0xbc,0x72
        ,0x13,0x26,0xd1,0xee,0x2a,0xf8,0x06,0xcc,0x31,0x54,0x75,0xcc,0x6f,0x0d
        ,0x9c,0x66,0xe1,0xb6,0x23,0x71,0xd4,0x5c,0xe2,0x39,0x2e,0x1a,0xc9,0x28
        ,0x44,0xc3,0x10,0x10,0x2f,0x15,0x6a,0x0d,0x8d,0x52,0xc1,0xf4,0xc4,0x0b
        ,0xa3,0xaa,0x65,0x09,0x57,0x86,0xcb,0x76,0x97,0x57,0xa6,0x56,0x3b,0xa9
        ,0x58,0xfe,0xd0,0xbc,0xc9,0x84,0xe8,0xb5,0x17,0xa3,0xd5,0xf5,0x15,0xb2
        ,0x3b,0x8a,0x41,0xe7,0x4a,0xa8,0x67,0x69,0x3f,0x90,0xdf,0xb0,0x61,0xa6
        ,0xe8,0x6d,0xfa,0xae,0xe6,0x44,0x72,0xc0,0x0e,0x5f,0x20,0x94,0x57,0x29
        ,0xcb,0xeb,0xe7,0x7f,0x06,0xce,0x78,0xe0,0x8f,0x40,0x98,0xfb,0xa4,0x1f
        ,0x9d,0x61,0x93,0xc0,0x31,0x7e,0x8b,0x60,0xd4,0xb6,0x08,0x4a,0xcb,0x42
        ,0xd2,0x9e,0x38,0x08,0xa3,0xbc,0x37,0x2d,0x85,0xe3,0x31,0x17,0x0f,0xcb
        ,0xf7,0xcc,0x72,0xd0,0xb7,0x1c,0x29,0x66,0x48,0xb3,0xa4,0xd1,0x0f,0x41
        ,0x62,0x95,0xd0,0x80,0x7a,0xa6,0x25,0xca,0xb2,0x74,0x4f,0xd9,0xea,0x8f
        ,0xd2,0x23,0xc4,0x25,0x37,0x02,0x98,0x28,0xbd,0x16,0xbe,0x02,0x54,0x6f
        ,0x13,0x0f,0xd2,0xe3,0x3b,0x93,0x6d,0x26,0x76,0xe0,0x8a,0xed,0x1b,0x73
        ,0x31,0x8b,0x75,0x0a,0x01,0x67,0xd0]
    salt = [0xde,0xe9,0x59,0xc7,0xe0,0x64,0x11,0x36,0x14,0x20,0xff,0x80,0x18,0x5e
           ,0xd5,0x7f,0x3e,0x67,0x76,0xaf]
    sig = [0x90,0x74,0x30,0x8f,0xb5,0x98,0xe9,0x70,0x1b,0x22,0x94,0x38,0x8e,0x52
          ,0xf9,0x71,0xfa,0xac,0x2b,0x60,0xa5,0x14,0x5a,0xf1,0x85,0xdf,0x52,0x87
          ,0xb5,0xed,0x28,0x87,0xe5,0x7c,0xe7,0xfd,0x44,0xdc,0x86,0x34,0xe4,0x07
          ,0xc8,0xe0,0xe4,0x36,0x0b,0xc2,0x26,0xf3,0xec,0x22,0x7f,0x9d,0x9e,0x54
          ,0x63,0x8e,0x8d,0x31,0xf5,0x05,0x12,0x15,0xdf,0x6e,0xbb,0x9c,0x2f,0x95
          ,0x79,0xaa,0x77,0x59,0x8a,0x38,0xf9,0x14,0xb5,0xb9,0xc1,0xbd,0x83,0xc4
          ,0xe2,0xf9,0xf3,0x82,0xa0,0xd0,0xaa,0x35,0x42,0xff,0xee,0x65,0x98,0x4a
          ,0x60,0x1b,0xc6,0x9e,0xb2,0x8d,0xeb,0x27,0xdc,0xa1,0x2c,0x82,0xc2,0xd4
          ,0xc3,0xf6,0x6c,0xd5,0x00,0xf1,0xff,0x2b,0x99,0x4d,0x8a,0x4e,0x30,0xcb
          ,0xb3,0x3c]

-- ftp://ftp.rsa.com/pub/rsalabs/tmp/pkcs1v15sign-vectors.txt
testPKCSVectors :: [(ByteString, RSA Word1024 SHA1 PKCS SignMode)] -- Message,Signature
testPKCSVectors = [(BS.pack m, fromInteger $ os2ip $ BS.pack sig)]
  where
    m = [0xcd,0xc8,0x7d,0xa2,0x23,0xd7,0x86,0xdf,0x3b,0x45,0xe0,0xbb,0xbc,0x72
        ,0x13,0x26,0xd1,0xee,0x2a,0xf8,0x06,0xcc,0x31,0x54,0x75,0xcc,0x6f,0x0d
        ,0x9c,0x66,0xe1,0xb6,0x23,0x71,0xd4,0x5c,0xe2,0x39,0x2e,0x1a,0xc9,0x28
        ,0x44,0xc3,0x10,0x10,0x2f,0x15,0x6a,0x0d,0x8d,0x52,0xc1,0xf4,0xc4,0x0b
        ,0xa3,0xaa,0x65,0x09,0x57,0x86,0xcb,0x76,0x97,0x57,0xa6,0x56,0x3b,0xa9
        ,0x58,0xfe,0xd0,0xbc,0xc9,0x84,0xe8,0xb5,0x17,0xa3,0xd5,0xf5,0x15,0xb2
        ,0x3b,0x8a,0x41,0xe7,0x4a,0xa8,0x67,0x69,0x3f,0x90,0xdf,0xb0,0x61,0xa6
        ,0xe8,0x6d,0xfa,0xae,0xe6,0x44,0x72,0xc0,0x0e,0x5f,0x20,0x94,0x57,0x29
        ,0xcb,0xeb,0xe7,0x7f,0x06,0xce,0x78,0xe0,0x8f,0x40,0x98,0xfb,0xa4,0x1f
        ,0x9d,0x61,0x93,0xc0,0x31,0x7e,0x8b,0x60,0xd4,0xb6,0x08,0x4a,0xcb,0x42
        ,0xd2,0x9e,0x38,0x08,0xa3,0xbc,0x37,0x2d,0x85,0xe3,0x31,0x17,0x0f,0xcb
        ,0xf7,0xcc,0x72,0xd0,0xb7,0x1c,0x29,0x66,0x48,0xb3,0xa4,0xd1,0x0f,0x41
        ,0x62,0x95,0xd0,0x80,0x7a,0xa6,0x25,0xca,0xb2,0x74,0x4f,0xd9,0xea,0x8f
        ,0xd2,0x23,0xc4,0x25,0x37,0x02,0x98,0x28,0xbd,0x16,0xbe,0x02,0x54,0x6f
        ,0x13,0x0f,0xd2,0xe3,0x3b,0x93,0x6d,0x26,0x76,0xe0,0x8a,0xed,0x1b,0x73
        ,0x31,0x8b,0x75,0x0a,0x01,0x67,0xd0]
    sig = [0x6b,0xc3,0xa0,0x66,0x56,0x84,0x29,0x30,0xa2,0x47,0xe3,0x0d,0x58,0x64
          ,0xb4,0xd8,0x19,0x23,0x6b,0xa7,0xc6,0x89,0x65,0x86,0x2a,0xd7,0xdb,0xc4
          ,0xe2,0x4a,0xf2,0x8e,0x86,0xbb,0x53,0x1f,0x03,0x35,0x8b,0xe5,0xfb,0x74
          ,0x77,0x7c,0x60,0x86,0xf8,0x50,0xca,0xef,0x89,0x3f,0x0d,0x6f,0xcc,0x2d
          ,0x0c,0x91,0xec,0x01,0x36,0x93,0xb4,0xea,0x00,0xb8,0x0c,0xd4,0x9a,0xac
          ,0x4e,0xcb,0x5f,0x89,0x11,0xaf,0xe5,0x39,0xad,0xa4,0xa8,0xf3,0x82,0x3d
          ,0x1d,0x13,0xe4,0x72,0xd1,0x49,0x05,0x47,0xc6,0x59,0xc7,0x61,0x7f,0x3d
          ,0x24,0x08,0x7d,0xdb,0x6f,0x2b,0x72,0x09,0x61,0x67,0xfc,0x09,0x7c,0xab
          ,0x18,0xe9,0xa4,0x58,0xfc,0xb6,0x34,0xcd,0xce,0x8e,0xe3,0x58,0x94,0xc4
          ,0x84,0xd7]

testPKCSSign :: PrivateKey Word1024 -> (ByteString, RSA Word1024 SHA1 PKCS SignMode) -> Assertion
testPKCSSign privk (m,sig) = sig @=? sign privk m

testPKCSVerify :: PublicKey Word1024 -> (ByteString, RSA Word1024 SHA1 PKCS SignMode) -> Assertion
testPKCSVerify pubk (m,sig) = assert $ verify pubk sig m

signPKCS :: Test
signPKCS = testGroup "Signing PKCS" $ map with testPKCSVectors
  where
    with t@(m,_) = testCase (shorten $ show m)  $ testPKCSSign testPrivKey t

verifyPKCS :: Test
verifyPKCS = testGroup "Verifying PKCS" $ map with testPKCSVectors
  where
    with t@(m,_) = testCase (shorten $ show m)  $ testPKCSVerify testPubKey t

tests :: [Test]
tests = [ signPKCS
        , verifyPKCS
        ]
