{-|

This module defines the hash instances for sha512 hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Curves.ED25519.Instance () where

import Control.Applicative ( (<$>) )
import Control.Monad       ( foldM )
import qualified Data.Vector.Unboxed as VU

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Hash
import Raaz.Core.Util.Ptr

import Raaz.Curves.ED25519.Type
import Raaz.Curves.ED25519.Ref
import Raaz.Curves.ED25519.CPortable ()
import Raaz.Curves.ED25519.Internal

