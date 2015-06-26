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
      , getRandomForSecret
      , toWord8List
      , fromWord8List
      , pointMult
      , encodePoint
      , getA
      , basepointB
      , getSignature
      , getHash
      , wordToByteString
      , ed25519l
      , decodePoint
      , isOnCurve
      , getSignature'
      , verify
      , W256(..)
      , W512(..)
      , word256ToW256
      , w256ToWord256
      , word512ToW512
      , w512ToWord512
      , Signature(..)
      , EDP25519(..)
       ) where

import Control.Applicative ( (<$>) )
import Data.Bits
-- import Data.Monoid
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
import qualified Data.ByteString                      as B

import qualified Data.Vector.Unboxed                  as VU
import           Data.Typeable       ( Typeable     )
import           Foreign.Ptr         ( castPtr      )

-- import           Raaz.Core.Classes
import           Raaz.Core.Parse.Applicative
-- import           Raaz.Core.Primitives
import           Raaz.Core.Write
import qualified Raaz.Core.Parse.Unsafe as PU
import qualified Raaz.Core.Write.Unsafe as WU


-- | The prime number (2^255 - 19)
q :: Integer
q = 57896044618658097711785492504343953926634992332820282019728792003956564819949
{-# INLINE q #-}

-- The number (q - 1)/4
ed25519c :: Integer
ed25519c = 14474011154664524427946373126085988481658748083205070504932198000989141204987
{-# INLINE ed25519c #-}

-- l = 2^252 + 27742317777372353535851937790883648493
ed25519l :: Integer
ed25519l = 7237005577332262213973186563042994240857116359379907606001950938285454250989
{-# INLINE ed25519l #-}

-- | Data type for numbers in the field - Modulo Prime q (2^255 - 19)
newtype EDP25519 = EDP25519 { edInt :: Integer } deriving (Show, Eq, Ord, Real, Modular)

-- | Reduce Integer to mod prime 'q'
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

-- timing-safe modular exponentiation
modexpo :: EDP25519 -> Integer -> Integer -> EDP25519
modexpo (EDP25519 g) k m = EDP25519 $ powModuloSlowSafe g k m

-- modular inverse
inv :: EDP25519 -> EDP25519
inv x = modexpo x (q - 2) q

-- the non-square parameter 'd'
d :: EDP25519
d = -121665 * (inv 121666)

i :: EDP25519
i = modexpo 2 ed25519c q

-- recover the positive 'x' coordinate corresponding to 'y'
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

baseX :: EDP25519
baseX = recoverPosX baseY

baseY :: EDP25519
baseY = 4 * (inv 5)

-- | The basepoint 'B'
basepointB :: Point
basepointB = Point baseX baseY

-- | Generates a random 32-byte number
getRandomForSecret :: IO W256
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

isOnCurve :: Point -> Bool
isOnCurve (Point x y) = (-x*x + y*y - 1 - d*x*x*y*y) == 0

encodePoint :: Point -> Word256
encodePoint (Point x y) = pEncoding
  where yEncoding = reverseWord $ fromInteger (edInt y)
        pEncoding = yEncoding .|. ((fromInteger $ edInt (x .&. 1)) `shiftL` 7)

decodePoint :: Word256 -> Point
decodePoint w = p
  where revW = fromIntegral $ reverseWord w
        y = EDP25519 $ revW .&. ((1 `shiftL` 255)-1)
        x' = recoverPosX y
        x = if (x' .&. 1) /= (((EDP25519 revW) `shiftR` 255) .&. 1)
            then 0 - x'
            else x'
        p = if isOnCurve(Point x y)
            then Point x y
            else undefined

-- changing endianness
reverseWord :: (Bits w, Num w, Storable w) => w -> w
reverseWord n = go (n, sizeOf n, 0)
  where go (_, 0, b) = b
        go (a, count, b) = let (a',b') = (a `shiftR` 8, a .&. 255)
                    in go (a', count-1, ((b `shiftL` 8) + b'))

-- break a Word into a list of Word8
toWord8List :: (Bits w, Num w, Integral w, Storable w) => w -> [Word8]
toWord8List w = go w [] (sizeOf w)
  where go _ l 0      = l
        go w' l count = go (w' `shiftR` 8) (fromIntegral (w' .&. 255) : l) (count-1)

fromWord8List :: (Bits w, Num w, Integral w, Storable w) => [Word8] -> w
fromWord8List [] = 0
fromWord8List (x:xs) = go x 0 xs
  where go a res []     = (res `shiftL` 8) .|. (fromIntegral a)
        go a res (y:ys) = go y ((res `shiftL` 8) .|. (fromIntegral a)) ys

-- returns the parameter 'A' given a hash value (integer form) 'h'
getA :: Integer -> Integer
getA h = (1 `shiftL` 254) + (go h 3)
  where go h' 253 = (1 `shiftL` 253) * (getBit h' 253)
        go h' i' = ((1 `shiftL` i') * (getBit h' i')) + (go h' (i'+1))

getBit :: Integer -> Int -> Integer
getBit a index
  | testBit a index = 1
  | otherwise       = 0

wordToByteString :: (Num w, Integral w, Bits w, Storable w) => w -> B.ByteString
wordToByteString w = B.pack $ toWord8List w

getHash :: B.ByteString -> (BE Word512)
getHash bs = fromWord8List . B.unpack . B.reverse . toByteString $ (hash bs :: SHA512)

-- | The 256-bit number for keys.
newtype W256 = W256 (VU.Vector (BE Word64)) deriving ( Show, Typeable )

-- | Timing independent equality testing.
instance Eq W256 where
 (==) (W256 g) (W256 h) = oftenCorrectEqVector g h

instance Storable W256 where
  sizeOf    _ = 4 * sizeOf (undefined :: (BE Word64))
  alignment _ = alignment  (undefined :: (BE Word64))
  peek  = unsafeRunParser w256parse . castPtr
    where w256parse = W256 <$> unsafeParseStorableVector 4

  poke ptr (W256 v) = unsafeWrite writeW256 cptr
    where writeW256 = writeStorableVector v
          cptr = castPtr ptr

instance EndianStore W256 where
  load = unsafeRunParser $ W256 <$> unsafeParseVector 4

  store cptr (W256 v) = unsafeWrite writeW256 cptr
    where writeW256 = writeVector v

-- | The 512-bit number for signature.
newtype W512 = W512 (VU.Vector (BE Word64)) deriving ( Show, Typeable )

-- | Timing independent equality testing.
instance Eq W512 where
 (==) (W512 g) (W512 h) = oftenCorrectEqVector g h

instance Storable W512 where
  sizeOf    _ = 8 * sizeOf (undefined :: (BE Word64))
  alignment _ = alignment  (undefined :: (BE Word64))
  peek  = unsafeRunParser w512parse . castPtr
    where w512parse = W512 <$> unsafeParseStorableVector 8

  poke ptr (W512 v) = unsafeWrite writeW512 cptr
    where writeW512 = writeStorableVector v
          cptr = castPtr ptr

instance EndianStore W512 where
  load = unsafeRunParser $ W512 <$> unsafeParseVector 8

  store cptr (W512 v) = unsafeWrite writeW512 cptr
    where writeW512 = writeVector v

w256ToWord256 :: W256 -> Word256
w256ToWord256 (W256 vec) = VU.foldl func (0 :: Word256) vec
  where func a b = (a `shiftL` 64) + (fromIntegral b)

word256ToW256 :: Word256 -> W256
word256ToW256 word256 = W256 $ VU.reverse (go (4 :: Int) word256 VU.empty)
  where go 0 _ v = v
        go n w v = go (n-1) (w `shiftR` 64) (VU.snoc v (fromIntegral $ w .&. 18446744073709551615))

w512ToWord512 :: W512 -> Word512
w512ToWord512 (W512 vec) = VU.foldl func (0 :: Word512) vec
  where func a b = (a `shiftL` 64) + (fromIntegral b)

word512ToW512 :: Word512 -> W512
word512ToW512 word512 = W512 $ VU.reverse (go (8 :: Int) word512 VU.empty)
  where go 0 _ v = v
        go n w v = go (n-1) (w `shiftR` 64) (VU.snoc v (fromIntegral $ w .&. 18446744073709551615))

-- | A 'SecretKey' - where the most significant bit of the last octet is
-- '1' if x is negative else '0' and the rest of the bits represent y in
-- the prime field space.
newtype SecretKey = SecretKey { sKey :: W256 } deriving (Show)

-- | A 'PublicKey' - where the most significant bit of the last octet is
-- '1' if x is negative else '0' and the rest of the bits represent y in
-- the prime field space.
newtype PublicKey = PublicKey { pKey :: W256 } deriving (Show)

-- | A 'Signature' - (does not include the message)
newtype Signature = Signature W512 deriving (Show)

instance Eq SecretKey where
  (==) (SecretKey w1) (SecretKey w2) = (w1  ==  w2)

instance Storable SecretKey where
  sizeOf _     = sizeOf (undefined :: W256)
  alignment _  = alignment (undefined :: W256)
  peek ptr     = PU.runParser (castPtr ptr) $ SecretKey <$> PU.parseStorable
  poke ptr k   = WU.runWrite (castPtr ptr) $ WU.writeStorable (sKey k)

-- | Stores individual words in Big Endian.
instance EndianStore SecretKey where
  load cptr    = PU.runParser cptr $ SecretKey <$> PU.parse
  store cptr k = WU.runWrite cptr  $ WU.write (sKey k)

instance Eq PublicKey where
  (==) (PublicKey w1) (PublicKey w2) = (w1  ==  w2)

instance Storable PublicKey where
  sizeOf _     = sizeOf (undefined :: W256)
  alignment _  = alignment (undefined :: W256)
  peek ptr     = PU.runParser (castPtr ptr) $ PublicKey <$> PU.parseStorable
  poke ptr k   = WU.runWrite (castPtr ptr) $ WU.writeStorable (pKey k)

-- | Stores individual words in Big Endian.
instance EndianStore PublicKey where
  load cptr    = PU.runParser cptr $ PublicKey <$> PU.parse
  store cptr k = WU.runWrite cptr  $ WU.write (pKey k)


-- | Returns the secret key given a random 256-bit number
getSecretKey :: W256 -> SecretKey
getSecretKey random = SecretKey random

-- | Returns the public key given a secret key
getPublicKey :: SecretKey -> PublicKey
getPublicKey (SecretKey skw') = PublicKey $ word256ToW256 encA
  where skw = w256ToWord256 skw'
        skByteString = B.pack $ toWord8List skw
        h = fromIntegral $ getHash skByteString
        a = getA h
        a' = pointMult a basepointB
        encA = encodePoint a'

-- | Returns the signature given a message as hexadecimal bytestring
getSignature :: SecretKey -> B.ByteString -> Signature
getSignature sk msg = getSignature' sk (getPublicKey sk) msg

getSignature' :: SecretKey -> PublicKey -> B.ByteString -> Signature
getSignature' (SecretKey skw') (PublicKey pkw') msg = Signature $ word512ToW512 sign
  where skw = w256ToWord256 skw'
        pkw = w256ToWord256 pkw'
        skByteString = B.pack $ toWord8List skw
        hashval = getHash skByteString
        h = fromIntegral hashval
        a = getA h
        m = unsafeFromHex msg
        upperh = (fromIntegral $ (reverseWord hashval) .&. ((1 `shiftL` 256)-1)) :: Word256
        rBS = B.append (wordToByteString upperh) m
        r = fromIntegral $ getHash rBS
        r' = pointMult r basepointB
        encR = encodePoint r'
        temp1 = wordToByteString encR
        temp2 = wordToByteString pkw
        temp = B.append temp1 (B.append temp2 m)
        s' = (r + ((fromIntegral (getHash temp)) * a)) `mod` ed25519l
        encS =  reverseWord $ (fromInteger s') :: Word256
        encR' = (fromIntegral encR) :: Word512
        encS' = (fromIntegral encS) :: Word512
        sign = (encR' `shiftL` 256) + encS'

verify :: PublicKey -> B.ByteString -> Signature -> Bool
verify (PublicKey pkw') msg (Signature sw')
  | (sizeOf sw /= 64) || (sizeOf pkw /= 32) = False
  | otherwise = result
    where sw = w512ToWord512 sw'
          pkw = w256ToWord256 pkw'
          encR = fromIntegral (sw `shiftR` 256)
          rPoint = decodePoint encR
          aPoint = decodePoint pkw
          s = fromIntegral ((reverseWord sw) `shiftR` 256)
          temp1 = wordToByteString encR
          temp2 = wordToByteString pkw
          temp3 = B.append (B.append temp1 temp2) (unsafeFromHex msg)
          h = fromIntegral $ getHash temp3
          result = if (pointMult s basepointB) /= (pointAdd rPoint (pointMult h aPoint))
                   then False
                   else True
