{- |

Exceptions which can be thrown by ECC

-}
{-# LANGUAGE DeriveDataTypeable #-}
module Raaz.ECC.Exception (ECCException(..)) where

import Data.Typeable
import Control.Exception

-- | Exceptions for ECC
data ECCException = IntegerTooLarge
                  | MessageRepresentativeOutOfRange
                  | CiphertextRepresentativeOutOfRange
                  | SignatureRepresentativeOutOfRange
                  | MessageTooLong
                  | DecryptionError
                  | EncodingError
                  | IntendedEncodedMessageLengthTooShort
                  | MaskTooLong
                  deriving (Eq,Show,Typeable)

-- | Exception instance
instance Exception ECCException
