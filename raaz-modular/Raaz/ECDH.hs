{-|

Elliptic Curve Diffie - Hellman Key exchange

-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
module Raaz.ECDH
       (
         Curve25519(..)
       -- * DH Types
       , SharedSecret
       , PublicNum
       , PrivateNum
       -- * DH exchange
       , generateParamsCurve25519
       , calculateSecretCurve25519
       , generateParamsNISTp192
       , calculateSecretNISTp192
       , module Raaz.KeyExchange
       ) where

import Raaz.Number
import Raaz.ECDH.Exchange
import Raaz.ECDH.Types

import Raaz.KeyExchange

instance KeyExchange (Curve25519 Word256) Word256 where
  generate curve r = generateParamsCurve25519 r curve
  getSecret curve = calculateSecretCurve25519 curve

instance KeyExchange (NISTp192 Word192) Word192 where
  generate curve r = generateParamsNISTp192 r curve
  getSecret curve = calculateSecretNISTp192 curve
