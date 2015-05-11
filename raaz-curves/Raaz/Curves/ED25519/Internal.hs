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
      , Point(..)
      , recoverPosX
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
      , decodePoint
      , isOnCurve
      , getSignature'
      , verify
       ) where

-- import Control.Applicative ( (<$>), (<*>) )
import Data.Bits
-- import Data.Monoid
-- import Data.Typeable
import Data.Word
-- import Foreign.Ptr         ( castPtr      )
-- import Foreign.Storable    ( peek, Storable(..) )
import Foreign.Storable    ( Storable(..) )

-- import Raaz.Core.Parse.Unsafe
import Raaz.Core.Random
import Raaz.Core.Types
-- import Raaz.Core.Write.Unsafe
import Raaz.Number
import Raaz.System.Random

import Raaz.Core.Primitives.Hash
import Raaz.Hash
import Raaz.Core.Util.ByteString
import qualified Data.ByteString       as B
-- import qualified Data.Vector.Generic   as G
-- import qualified Data.Vector.Unboxed   as VU

-- | The prime number (2^255 - 19)
q :: Integer
q = 57896044618658097711785492504343953926634992332820282019728792003956564819949
{-# INLINE q #-}

-- | The number (q - 1)/4
ed25519c :: Integer
ed25519c = 14474011154664524427946373126085988481658748083205070504932198000989141204987
{-# INLINE ed25519c #-}

-- |  l = 2^252 + 27742317777372353535851937790883648493
ed25519l :: Integer
ed25519l = 7237005577332262213973186563042994240857116359379907606001950938285454250989
{-# INLINE ed25519l #-}

modexpo :: EDP25519 -> Integer -> Integer -> EDP25519
modexpo (EDP25519 g) k m = EDP25519 $ powModuloSlowSafe g k m

inv :: EDP25519 -> EDP25519
inv x = modexpo x (q - 2) q

d :: EDP25519
d = -121665 * (inv 121666)

i :: EDP25519
i = modexpo 2 ed25519c q

recoverPosX :: EDP25519 -> EDP25519
recoverPosX y = getX x xx
  where xx = (y*y - 1) * (inv $ d*y*y + 1)
        x  = modexpo xx ((q+3) `shiftR` 3) q
        getX a b
          | root .&. 1 /= 0 = 0 - a
          | otherwise       = root
          where root
                  | (a*a - b) /= 0 = (a * i)
                  | otherwise      = a

baseY :: EDP25519
baseY = 4 * (inv 5)

baseX :: EDP25519
baseX = recoverPosX baseY

-- | The basepoint B.
basepointB :: Point
basepointB = Point baseX baseY


-- | Data type for numbers in the field - Modulo Prime q (2^255 - 19)
newtype EDP25519 = EDP25519 { edInt :: Integer } deriving (Show, Eq, Ord, Real, Modular)

-- | Reduced Integer to mod prime 'q'
narrowP25519 :: Integer -> Integer
narrowP25519 w = w `mod` q
{-# INLINE narrowP25519 #-}

instance Num EDP25519 where
  (+) (EDP25519 a) (EDP25519 b) = EDP25519 $ narrowP25519 (a + b)
  (-) (EDP25519 a) (EDP25519 b) = EDP25519 $ narrowP25519 (a - b)
  (*) (EDP25519 a) (EDP25519 b) = EDP25519 $ narrowP25519 (a * b)
  abs x                       = x
  signum 0                    = 0
  signum _                    = 1
  fromInteger                 = EDP25519 . narrowP25519

instance Bounded EDP25519 where
  minBound = 0
  maxBound = EDP25519 $ q - 1

instance Enum EDP25519 where
  succ x | x /= maxBound = x + 1
         | otherwise     = error "succ: EDP25519"
  pred x | x /= minBound = x - 1
         | otherwise     = error "pred: EDP25519"
  toEnum                 = EDP25519 . toEnum
  fromEnum (EDP25519 a)   = fromEnum a

instance Bits EDP25519 where
  (.&.)   (EDP25519 x) (EDP25519 y) = EDP25519 (x .&. y)
  (.|.)   (EDP25519 x) (EDP25519 y) = EDP25519 (x .|. y)
  xor     (EDP25519 x) (EDP25519 y) = EDP25519 (x `xor` y)
  complement (EDP25519 x)           = EDP25519 $ complement x
  shiftL  (EDP25519 w) n            = EDP25519 $ narrowP25519 $ shiftL w n
  shiftR  (EDP25519 w) n            = EDP25519 $ narrowP25519 $ shiftR w n
  rotateL (EDP25519 w) n            = EDP25519 $ narrowP25519 $ rotateL w n
  rotateR (EDP25519 w) n            = EDP25519 $ narrowP25519 $ rotateR w n
  bitSize  _                        = 256
  isSigned _                        = False
#if MIN_VERSION_base(4,6,0)
  popCount                          = popCountDefault
  bit                               = bitDefault
  testBit                           = testBitDefault
#endif


-- | A Point in the prime field space.
data Point = Point { pointX :: EDP25519, pointY :: EDP25519 } deriving (Eq, Show)

-- | A 'SecretKey' - where the last bit of the 256 bits is '1' if x is negative else '0'
-- and the rest of the bits represent y in the prime field space.
newtype SecretKey = SecretKey { unSecretKey :: (LE Word256) } deriving (Eq, Show)

-- | A 'PublicKey' - where the last bit of the 256 bits is '1' if x is negative else '0'
-- and the rest of the bits represent y in the prime field space.
newtype PublicKey = PublicKey { unPublicKey :: (LE Word256) } deriving (Eq, Show)

-- | Generate secret (P25519) from a random P25519 number as specified in
-- DJB's paper
getSecretFromRandom :: (LE Word256) -> (LE Word256)
getSecretFromRandom random = secret
  where
    temp1 = (((1 `shiftL` 248) - 1) `shiftL` 8) + 248
    -- temp1: (256 bit number with 248 1's followed by 248)
    temp2 = random .&. temp1
    -- (Rightmost-byte `AND` with 248)
    temp3 = (63 `shiftL` 248) .|. ((1 `shiftL` 248) - 1)
    -- temp3: (256 bit number with 63 followed by 248 1's)
    temp4 = temp2 .&. temp3
    -- (Leftmost-byte `AND` with 63)
    temp5 = 64 `shiftL` 248
    -- temp5: (256 bit number with 64 followed by 248 1's)
    secret = temp4 .|. temp5
    -- (Leftmost-byte `OR` with 64)

-- | Generates a random 32-byte number
getRandomForSecret :: IO (LE Word256)
getRandomForSecret = do
  stdPRG <- ((newPRG undefined) :: (IO SystemPRG))
  fromPRG stdPRG

pointAdd :: Point -> Point -> Point
pointAdd (Point x1 y1) (Point x2 y2) = Point x3 y3
  where x3 = (x1*y2 + x2*y1) * (inv $ 1 + d*x1*x2*y1*y2)
        y3 = (y1*y2 + x1*x2) * (inv $ 1 - d*x1*x2*y1*y2)

-- Computes kP from given point `basepoint`
pointMult :: Integer -> Point -> Point
pointMult 0 _ = Point 0 1
pointMult k basepoint = montgom nbits (Point 0 1) basepoint
  where
    nbits = numberOfBits' k 0
    numberOfBits' n count
     | n == 0    = count
     | otherwise = numberOfBits' (n `shiftR` 1) (count+1)
    montgom 0 r0 _ = r0
    montgom bitnum r0 r1
     | testBit k (bitnum - 1) = let r1r1 = pointAdd r1 r1
                              in montgom (bitnum-1) r0r1 r1r1
     | otherwise = let r0r0 = pointAdd r0 r0
                   in montgom (bitnum-1) r0r0 r0r1
     where r0r1 = pointAdd r0 r1

encodePoint :: Point -> (LE Word256)
encodePoint (Point x y) = pEncoding
  where yEncoding = reverseWord $ fromInteger (edInt y)
        pEncoding = yEncoding .|. ((fromInteger $ edInt (x .&. 1)) `shiftL` 7)

-- changing endianness
reverseWord :: (Bits w, Num w) => w -> w
reverseWord n = go (n,0)
  where go (0,b) = b
        go (a,b) = let (a',b') = (a `shiftR` 8,a .&. 255)
                    in go (a',((b `shiftL` 8) + b'))

-- changing endianness
reverseWord256 :: (Bits w, Num w) => w -> w
reverseWord256 n = go (n, 32 :: Integer, 0)
  where go (_, 0, b) = b
        go (a, count, b) = let (a',b') = (a `shiftR` 8, a .&. 255)
                    in go (a', count-1, ((b `shiftL` 8) + b'))

-- changing endianness
reverseWord512 :: (Bits w, Num w) => w -> w
reverseWord512 n = go (n, 64 :: Integer, 0)
  where go (_, 0, b) = b
        go (a, count, b) = let (a',b') = (a `shiftR` 8, a .&. 255)
                    in go (a', count-1, ((b `shiftL` 8) + b'))

-- byteSwap64 :: (LE Word64) -> (LE Word64)
-- byteSwap64 w =
--         (w `shift` (-56))                  .|. (w `shift` 56)
--     .|. ((w `shift` (-40)) .&. 0xff00)     .|. ((w .&. 0xff00) `shift` 40)
--     .|. ((w `shift` (-24)) .&. 0xff0000)   .|. ((w .&. 0xff0000) `shift` 24)
--     .|. ((w `shift` (-8))  .&. 0xff000000) .|. ((w .&. 0xff000000) `shift` 8)

toWord8List :: (Bits w, Num w, Integral w) => w -> Int -> [Word8]
toWord8List w n = go w [] n
  where go _ l 0     = reverse l
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
  where go h' 253 = (1 `shiftL` 253) * (getBit h' 253)
        go h' i' = ((1 `shiftL` i') * (getBit h' i')) + (go h' (i'+1))

getBit :: Integer -> Int -> Integer
getBit a index
  | testBit a index = 1
  | otherwise       = 0

getSecretKey :: (LE Word256) -> SecretKey
getSecretKey random = SecretKey $ getSecretFromRandom random

getBSfromWord :: (Num w, Integral w, Bits w, Storable w) => w -> B.ByteString
getBSfromWord w = B.pack $ toWord8List w (sizeOf w)

getHashBS :: B.ByteString -> (BE Word512)
getHashBS bs = fromWord8List . B.unpack . B.reverse . toByteString $ getSHA512 bs

getPublicKey :: SecretKey -> PublicKey
getPublicKey (SecretKey skw) = PublicKey encA
  where skByteString = B.pack $ (toWord8List skw 32)
        h = fromIntegral $ getHashBS skByteString
        a = getA h
        a' = pointMult a basepointB
        encA = encodePoint a'

newtype Signature = Signature (LE Word512) deriving (Eq, Show)

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
        encS =  reverseWord256 $ (fromInteger s') :: (LE Word256)
        encR' = (fromIntegral encR) :: (LE Word512)
        encS' = (fromIntegral encS) :: (LE Word512)
        sign = (encR' `shiftL` 256) + encS'

getSignature' :: B.ByteString -> SecretKey -> Signature
getSignature' msg sk = getSignature msg sk pk
  where pk = getPublicKey sk

isOnCurve :: Point -> Bool
isOnCurve (Point x y) = (-x*x + y*y - 1 -d*x*x*y*y) == 0

decodePoint :: (LE Word256) -> Point
decodePoint w = p
  where revW = fromIntegral $ reverseWord256 w
        y = fromIntegral $ revW .&. ((1 `shiftL` 255)-1)
        x' = recoverPosX y
        x = if (x' .&. 1) /= ((revW `shiftR` 255) .&. 1)
            then 0 - x'
            else x'
        p = if isOnCurve(Point x y)
            then Point x y
            else undefined

verify :: PublicKey -> B.ByteString -> Signature -> Bool
verify (PublicKey pkw) msg (Signature sw)
  | (sizeOf sw /= 64) || (sizeOf pkw /= 32) = False
  | otherwise = result
    where encR = fromIntegral (sw `shiftR` 256)
          rPoint = decodePoint encR
          aPoint = decodePoint pkw
          s = fromIntegral ((reverseWord512 sw) `shiftR` 256)
          temp1 = getBSfromWord encR
          temp2 = getBSfromWord pkw
          temp3 = B.append (B.append temp1 temp2) (unsafeFromHex msg)
          h = fromIntegral $ getHashBS temp3
          result = if (pointMult s basepointB) /= (pointAdd rPoint (pointMult h aPoint))
                   then False
                   else True
