{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE GADTs #-}

module Raaz.Core.Random
  ( DevRandom(..)
  , getRandomWord8From
  , getRandomWord16From
  , getRandomWord32From
  , getRandomWord64From
  , getRandomWord128From
  , getRandomWord256From
  , getRandomWord512From
  , getNRandomBytes
  ) where

import           Foreign.Marshal (allocaBytes)
import           Foreign.Ptr (castPtr)
import           Foreign.Storable (peek, Storable)
import           System.IO (openBinaryFile, hGetBuf, Handle, IOMode(..))
import           System.IO.Unsafe (unsafePerformIO)

data DevRandom = DevRandom | DevURandom deriving (Eq, Show)

devRandom :: Handle
devRandom = unsafePerformIO (openBinaryFile "/dev/random" ReadMode)

devURandom :: Handle
devURandom = unsafePerformIO (openBinaryFile "/dev/urandom" ReadMode)

dev :: DevRandom -> Handle
dev DevRandom = devRandom
dev DevURandom = devURandom

getRandomWord8From :: Storable a => DevRandom -> IO a
getRandomWord8From src = allocaBytes 1 $ \buf -> do
  1 <- hGetBuf (dev src) buf 1
  peek buf

getRandomWord16From :: Storable a => DevRandom -> IO a
getRandomWord16From src = allocaBytes 2 $ \buf -> do
  2 <- hGetBuf (dev src) buf 2
  peek (castPtr buf)

getRandomWord32From :: Storable a => DevRandom -> IO a
getRandomWord32From src = allocaBytes 4 $ \buf -> do
  4 <- hGetBuf (dev src) buf 4
  peek (castPtr buf)

getRandomWord64From :: Storable a => DevRandom -> IO a
getRandomWord64From src = allocaBytes 8 $ \buf -> do
  8 <- hGetBuf (dev src) buf 8
  peek (castPtr buf)

getRandomWord128From :: Storable a => DevRandom -> IO a
getRandomWord128From src = allocaBytes 16 $ \buf -> do
  16 <- hGetBuf (dev src) buf 16
  peek (castPtr buf)

getRandomWord256From :: Storable a => DevRandom -> IO a
getRandomWord256From src = allocaBytes 32 $ \buf -> do
  32 <- hGetBuf (dev src) buf 32
  peek (castPtr buf)

getRandomWord512From :: Storable a => DevRandom -> IO a
getRandomWord512From src = allocaBytes 64 $ \buf -> do
  64 <- hGetBuf (dev src) buf 64
  peek (castPtr buf)

getNRandomBytes :: Storable a => DevRandom -> Int -> IO a
getNRandomBytes src nBytes = allocaBytes nBytes $ \buf -> do
  _ <- hGetBuf (dev src) buf nBytes
  peek (castPtr buf)
