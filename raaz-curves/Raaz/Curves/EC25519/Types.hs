{-|

This module exposes the `EC25519` curve constructor.

-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FunctionalDependencies #-}

module Raaz.Curves.EC25519.Types
       () where

import Data.Bits ()
import Foreign.Storable

--data EC25519 w = EC25519 deriving (Eq, Show)

