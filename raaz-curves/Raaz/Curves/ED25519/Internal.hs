{- |

This module gives the reference implementation of the ECDSA functions
over Edwards curve Ed25519. There is a faster recommended implementation
available. So you /should not/ be using this code in production unless
you know what you are doing.

-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE InstanceSigs               #-}
{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE CPP                        #-}
module Raaz.Curves.ED25519.Internal
      ( getSecretKey
      , getPublicKey
      , SecretKey(..)
      , PublicKey(..)
      , reverseWord
      , reverseWord256
      , reverseWord512
      , getRandomForSecret
      , toWord8List
      , fromWord8List
      , pointMult
      , encodePoint
      , getA
      , basepointB
      , getSignature
      , getHashBS
      , getBSfromWord
      , ed25519l
       ) where

import Control.Applicative ( (<$>), (<*>) )
import Data.Bits
import Data.Monoid
import Data.Typeable
import Data.Word
import Foreign.Ptr         ( castPtr      )
import Foreign.Storable    ( peek, Storable(..) )

import Raaz.Core.DH
import Raaz.Core.Parse.Unsafe
import Raaz.Core.Random
import Raaz.Core.Types
import Raaz.Core.Write.Unsafe
import Raaz.Number
import Raaz.System.Random

import Raaz.Core.Primitives
import Raaz.Core.Primitives.Hash
import Raaz.Hash
import Raaz.Core.Util.ByteString
import qualified Data.ByteString       as B
import qualified Data.ByteString.Char8 as C
import qualified Data.Vector.Generic   as G
import qualified Data.Vector.Unboxed   as VU


-- | The parameter number of bits 'b'
ed25519b :: Integer
ed25519b = 256
{-# INLINE ed25519b #-}

-- | The prime number (2^255 - 19)
q :: Integer
q = 57896044618658097711785492504343953926634992332820282019728792003956564819949
{-# INLINE q #-}

-- | The number (ed25519q - 1)/4
ed25519c :: Integer
ed25519c = 14474011154664524427946373126085988481658748083205070504932198000989141204987
{-# INLINE ed25519c #-}

-- |  l = 2^252 + 27742317777372353535851937790883648493
ed25519l :: Integer
ed25519l = 7237005577332262213973186563042994240857116359379907606001950938285454250989
{-# INLINE ed25519l #-}

modexpo :: Integer -> Integer -> Integer -> Integer
modexpo = powModuloSlowSafe

inv :: Integer -> Integer
inv x = modexpo x (q - 2) q

d :: Integer
d = -121665 * (inv 121666)

i :: Integer
i = modexpo 2 ed25519c q

recoverPosX :: Integer -> Integer
recoverPosX y = getX x xx
  where xx = (y*y - 1) * (inv $ d*y*y + 1)
        x  = modexpo xx ((q+3) `shiftR` 3) q
        getX a b
          | root `mod` 2 /= 0 = q - a
          | otherwise         = root
          where root
                  | ((a*a - b) `mod` q) /= 0 = (a * i) `mod` q
                  | otherwise                = a

baseY :: Integer
baseY = 4 * (inv 5)

baseX :: Integer
baseX = recoverPosX baseY

-- | The basepoint B.
basepointB :: Point
basepointB = Point baseX baseY

-- | Data type for numbers in the field - Modulo Prime curve25519P (2^255 - 19)
-- in Little-endian representation (same as the recommended implementation)
data P25519 = P25519 {-# UNPACK #-} !(LE Word64)
                     {-# UNPACK #-} !(LE Word64)
                     {-# UNPACK #-} !(LE Word64)
                     {-# UNPACK #-} !(LE Word64) deriving (Show, Typeable)

-- | Reduce integer to modulo prime curve25519P
narrowP25519 :: Integer -> Integer
narrowP25519 w = w `mod` q
{-# INLINE narrowP25519 #-}

-- | Convert a P25519 number to Integer
p25519toInteger :: P25519 -> Integer
p25519toInteger (P25519 a0 a1 a2 a3) = i
  where i0 = toInteger a0
        i1 = toInteger a1
        i2 = toInteger a2
        i3 = toInteger a3
        i  = (i3 `shiftL` 192) + (i2 `shiftL` 128) + (i1 `shiftL` 64) + i0

-- | Convert an integer to P25519
integerToP25519 :: Integer -> P25519
integerToP25519 i = P25519 p0 p1 p2 p3
  where x  = narrowP25519 i
        p0 = fromInteger $ x .&. ((1 `shiftL` 64) - 1)
        p1 = fromInteger $ (x `shiftR` 64) .&. ((1 `shiftL` 64) - 1)
        p2 = fromInteger $ (x `shiftR` 128) .&. ((1 `shiftL` 64) - 1)
        p3 = fromInteger $ (x `shiftR` 192) .&. ((1 `shiftL` 64) - 1)

-------------------- Instances for the type P25519 ----------------------------
-- | Timing independent equality testing.
instance Eq P25519 where
  (==) (P25519 g0 g1 g2 g3) (P25519 h0 h1 h2 h3) = xor g0 h0
                                               .|. xor g1 h1
                                               .|. xor g2 h2
                                               .|. xor g3 h3
                                                == 0
-- | Storable class instance
instance Storable P25519 where
  sizeOf    _ = 4 * sizeOf (undefined :: (LE Word64))
  alignment _ = alignment  (undefined :: (LE Word64))
  peek ptr = runParser cptr parseP25519
    where parseP25519 = P25519 <$> parseStorable
                               <*> parseStorable
                               <*> parseStorable
                               <*> parseStorable
          cptr = castPtr ptr

  poke ptr (P25519 h0 h1 h2 h3) = runWrite cptr writeP25519
    where writeP25519 = writeStorable h0
                     <> writeStorable h1
                     <> writeStorable h2
                     <> writeStorable h3
          cptr = castPtr ptr

-- | EndianStore class instance
instance EndianStore P25519 where
  load cptr = runParser cptr parseP25519
    where parseP25519 = P25519 <$> parse
                               <*> parse
                               <*> parse
                               <*> parse

  store cptr (P25519 h0 h1 h2 h3) = runWrite cptr writeP25519
    where writeP25519 = write h0
                     <> write h1
                     <> write h2
                     <> write h3

-- | A Point in the prime field space.
data Point = Point { pointX :: Integer, pointY :: Integer } deriving (Eq, Show)

-- | A 'SecretKey' - where the last bit of the 256 bits is '1' if x is negative else '0'
-- and the rest of the bits represent y in the prime field space.
newtype SecretKey = SecretKey { unSecretKey :: (Word256) } deriving (Eq, Show)

-- | A 'PublicKey' - where the last bit of the 256 bits is '1' if x is negative else '0'
-- and the rest of the bits represent y in the prime field space.
newtype PublicKey = PublicKey { unPublicKey :: (Word256) } deriving (Eq, Show)

-- | Generate secret (P25519) from a random P25519 number as specified in
-- DJB's paper
getSecretFromRandom :: Word256 -> Word256
getSecretFromRandom iRandom = secret
  where
    temp1 = (((1 `shiftL` 248) - 1) `shiftL` 8) + 248
    -- temp1: (256 bit number with 248 1's followed by 248)
    temp2 = iRandom .&. temp1
    -- (Rightmost-byte `AND` with 248)
    temp3 = (63 `shiftL` 248) .|. ((1 `shiftL` 248) - 1)
    -- temp3: (256 bit number with 63 followed by 248 1's)
    temp4 = temp2 .&. temp3
    -- (Leftmost-byte `AND` with 63)
    temp5 = 64 `shiftL` 248
    -- temp5: (256 bit number with 64 followed by 248 1's)
    iSecret = temp4 .|. temp5
    -- (Leftmost-byte `OR` with 64)
    secret = iSecret

-- | Generates a random P25519 (`mod` curve25519P) number using the system's
-- PRG(eg: /dev/urandom/)
getRandomP25519 :: IO P25519
getRandomP25519 = do
  stdPRG <- ((newPRG undefined) :: (IO SystemPRG))
  p <- fromPRG stdPRG
  return $ integerToP25519 (narrowP25519 (p25519toInteger p))

-- | Generates a random 32-byte number
getRandomForSecret :: IO Word256
getRandomForSecret = do
  stdPRG <- ((newPRG undefined) :: (IO SystemPRG))
  fromPRG stdPRG

pointAdd :: Point -> Point -> Point
pointAdd (Point x1 y1) (Point x2 y2) = Point (x3 `mod` q) (y3 `mod` q)
  where x3 = (x1*y2 + x2*y1) * (inv $ 1 + d*x1*x2*y1*y2)
        y3 = (y1*y2 + x1*x2) * (inv $ 1 - d*x1*x2*y1*y2)

-- Computes kP from given point `basepoint`
pointMult :: Integer -> Point -> Point
pointMult 0 _ = Point 0 1
pointMult k basepoint = montgom nbits (Point 0 1) basepoint
  where
    nbits = numberOfBits k 0
    numberOfBits n count
     | n == 0    = count
     | otherwise = numberOfBits (n `shiftR` 1) (count+1)
    montgom 0 r0 _ = r0
    montgom bitnum r0 r1
     | testBit k (bitnum - 1) = let r1r1 = pointAdd r1 r1
                              in montgom (bitnum-1) r0r1 r1r1
     | otherwise = let r0r0 = pointAdd r0 r0
                   in montgom (bitnum-1) r0r0 r0r1
     where r0r1 = pointAdd r0 r1

encodePoint :: Point -> Word256
encodePoint (Point x y) = pEncoding
  where yEncoding = reverseWord $ fromInteger y
        pEncoding = yEncoding .|. ((fromInteger $ x .&. 1) `shiftL` 7)

-- chanding endianness
reverseWord :: (Bits w, Num w) => w -> w
reverseWord n = go (n,0)
  where go (0,b) = b
        go (a,b) = let (a',b') = (a `shiftR` 8,a .&. 255)
                    in go (a',((b `shiftL` 8) + b'))

-- chanding endianness
reverseWord256 :: (Bits w, Num w) => w -> w
reverseWord256 n = go (n,32,0)
  where go (n,0,b) = b
        go (a,count,b) = let (a',b') = (a `shiftR` 8,a .&. 255)
                    in go (a',count-1,((b `shiftL` 8) + b'))

-- chanding endianness
reverseWord512 :: (Bits w, Num w) => w -> w
reverseWord512 n = go (n,64,0)
  where go (n,0,b) = b
        go (a,count,b) = let (a',b') = (a `shiftR` 8,a .&. 255)
                    in go (a',count-1,((b `shiftL` 8) + b'))

byteSwap64 :: (LE Word64) -> (LE Word64)
byteSwap64 w =
        (w `shift` (-56))                  .|. (w `shift` 56)
    .|. ((w `shift` (-40)) .&. 0xff00)     .|. ((w .&. 0xff00) `shift` 40)
    .|. ((w `shift` (-24)) .&. 0xff0000)   .|. ((w .&. 0xff0000) `shift` 24)
    .|. ((w `shift` (-8))  .&. 0xff000000) .|. ((w .&. 0xff000000) `shift` 8)

toWord8List :: (Bits w, Num w, Integral w) => w -> Int -> [Word8]
toWord8List w n = go w [] n
  where go w' l 0     = reverse l
        go w' l count = go (w' `shiftR` 8) (l ++ [fromIntegral (w' .&. 255)]) (count-1)

fromWord8List :: (Bits w, Num w, Integral w) => [Word8] -> w
fromWord8List [] = 0
fromWord8List (x:xs) = go x 0 xs
  where go a res []     = (res `shiftL` 8) .|. (fromIntegral a)
        go a res (y:ys) = go y ((res `shiftL` 8) .|. (fromIntegral a)) ys

getSHA512 :: B.ByteString -> SHA512
getSHA512 m = hash m

getA :: Integer -> Integer
getA h = (1 `shiftL` 254) + (go h 3)
  where go h 253 = (1 `shiftL` 253) * (getBit h 253)
        go h i = ((1 `shiftL` i) * (getBit h i)) + (go h (i+1))

getBit :: Integer -> Int -> Integer
getBit a i
  | testBit a i = 1
  | otherwise   = 0

getSecretKey :: Word256 -> SecretKey
getSecretKey random = SecretKey $ getSecretFromRandom random

getBSfromWord :: (Num w, Integral w, Bits w, Storable w) => w -> B.ByteString
getBSfromWord w = B.pack $ toWord8List w (sizeOf w)

getHashBS :: B.ByteString -> Word512
getHashBS bs = fromWord8List . B.unpack . B.reverse . unsafeFromHex . toHex $ getSHA512 bs

getPublicKey :: SecretKey -> PublicKey
getPublicKey sk@(SecretKey skw) = PublicKey encA
  where skByteString = B.pack $ (toWord8List skw 32)
        h = fromIntegral $ getHashBS skByteString
        -- h = reverseWord512 (fromByteStringStorable (unsafeFromHex (toHex (getSHA512 skByteString))) :: Word512)
        a = getA h
        capA = pointMult a basepointB
        encA = encodePoint capA

newtype Signature = Signature { unSignature :: Word512 } deriving (Eq, Show)

getSignature :: B.ByteString -> SecretKey -> PublicKey -> Signature
getSignature msg (SecretKey skw) (PublicKey pkw) = Signature sign
  where skByteString = B.pack $ (toWord8List skw 32)
        h = fromIntegral $ getHashBS skByteString
        a = getA h
        upperh = (fromIntegral ((reverseWord512 h) .&. ((1 `shiftL` 256)-1))) :: Word256
        rBS = B.append (getBSfromWord upperh) (unsafeFromHex msg)
        r = fromIntegral $ getHashBS rBS
        r' = pointMult r basepointB
        encR = encodePoint r'
        temp1 = getBSfromWord encR
        temp2 = getBSfromWord pkw
        temp = B.append temp1 (B.append temp2 (unsafeFromHex msg))
        s' = (r + ((fromIntegral (getHashBS temp)) * a)) `mod` ed25519l
        encS =  reverseWord256 $ (fromInteger s') :: Word256
        encR' = (fromIntegral encR) :: Word512
        encS' = (fromIntegral encS) :: Word512
        sign = (encR' `shiftL` 256) + encS'

isOnCurve :: Point -> Bool
isOnCurve (Point x y) = (-x*x + y*y - 1 -d*x*x*y*y) `mod` q == 0
