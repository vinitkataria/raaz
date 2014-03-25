{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE TypeFamilies         #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CBC.Instance where

import Raaz.Primitives
import Raaz.Primitives.Cipher

import Raaz.Cipher.AES.CBC.Ref ()
import Raaz.Cipher.AES.CBC.CPortable ()
import Raaz.Cipher.AES.Internal

instance CryptoPrimitive (Cipher (AES CBC) KEY128 Encryption) where
  type Recommended (Cipher (AES CBC) KEY128 Encryption) = CGadget (Cipher (AES CBC) KEY128 Encryption)
  type Reference (Cipher (AES CBC) KEY128 Encryption) = HGadget (Cipher (AES CBC) KEY128 Encryption)

instance CryptoPrimitive (Cipher (AES CBC) KEY128 Decryption) where
  type Recommended (Cipher (AES CBC) KEY128 Decryption) = CGadget (Cipher (AES CBC) KEY128 Decryption)
  type Reference (Cipher (AES CBC) KEY128 Decryption) = HGadget (Cipher (AES CBC) KEY128 Decryption)

instance CryptoPrimitive (Cipher (AES CBC) KEY192 Encryption) where
  type Recommended (Cipher (AES CBC) KEY192 Encryption) = CGadget (Cipher (AES CBC) KEY192 Encryption)
  type Reference (Cipher (AES CBC) KEY192 Encryption) = HGadget (Cipher (AES CBC) KEY192 Encryption)

instance CryptoPrimitive (Cipher (AES CBC) KEY192 Decryption) where
  type Recommended (Cipher (AES CBC) KEY192 Decryption) = CGadget (Cipher (AES CBC) KEY192 Decryption)
  type Reference (Cipher (AES CBC) KEY192 Decryption) = HGadget (Cipher (AES CBC) KEY192 Decryption)

instance CryptoPrimitive (Cipher (AES CBC) KEY256 Encryption) where
  type Recommended (Cipher (AES CBC) KEY256 Encryption) = CGadget (Cipher (AES CBC) KEY256 Encryption)
  type Reference (Cipher (AES CBC) KEY256 Encryption) = HGadget (Cipher (AES CBC) KEY256 Encryption)

instance CryptoPrimitive (Cipher (AES CBC) KEY256 Decryption) where
  type Recommended (Cipher (AES CBC) KEY256 Decryption) = CGadget (Cipher (AES CBC) KEY256 Decryption)
  type Reference (Cipher (AES CBC) KEY256 Decryption) = HGadget (Cipher (AES CBC) KEY256 Decryption)

instance HasInverse (HGadget (Cipher (AES CBC) KEY128 Encryption)) where
  type Inverse (HGadget (Cipher (AES CBC) KEY128 Encryption)) = HGadget (Cipher (AES CBC) KEY128 Decryption)

instance HasInverse (HGadget (Cipher (AES CBC) KEY128 Decryption)) where
  type Inverse (HGadget (Cipher (AES CBC) KEY128 Decryption)) = HGadget (Cipher (AES CBC) KEY128 Encryption)

instance HasInverse (HGadget (Cipher (AES CBC) KEY192 Encryption)) where
  type Inverse (HGadget (Cipher (AES CBC) KEY192 Encryption)) = HGadget (Cipher (AES CBC) KEY192 Decryption)

instance HasInverse (HGadget (Cipher (AES CBC) KEY192 Decryption)) where
  type Inverse (HGadget (Cipher (AES CBC) KEY192 Decryption)) = HGadget (Cipher (AES CBC) KEY192 Encryption)

instance HasInverse (HGadget (Cipher (AES CBC) KEY256 Encryption)) where
  type Inverse (HGadget (Cipher (AES CBC) KEY256 Encryption)) = HGadget (Cipher (AES CBC) KEY256 Decryption)

instance HasInverse (HGadget (Cipher (AES CBC) KEY256 Decryption)) where
  type Inverse (HGadget (Cipher (AES CBC) KEY256 Decryption)) = HGadget (Cipher (AES CBC) KEY256 Encryption)

instance HasInverse (CGadget (Cipher (AES CBC) KEY128 Encryption)) where
  type Inverse (CGadget (Cipher (AES CBC) KEY128 Encryption)) = CGadget (Cipher (AES CBC) KEY128 Decryption)

instance HasInverse (CGadget (Cipher (AES CBC) KEY128 Decryption)) where
  type Inverse (CGadget (Cipher (AES CBC) KEY128 Decryption)) = CGadget (Cipher (AES CBC) KEY128 Encryption)

instance HasInverse (CGadget (Cipher (AES CBC) KEY192 Encryption)) where
  type Inverse (CGadget (Cipher (AES CBC) KEY192 Encryption)) = CGadget (Cipher (AES CBC) KEY192 Decryption)

instance HasInverse (CGadget (Cipher (AES CBC) KEY192 Decryption)) where
  type Inverse (CGadget (Cipher (AES CBC) KEY192 Decryption)) = CGadget (Cipher (AES CBC) KEY192 Encryption)

instance HasInverse (CGadget (Cipher (AES CBC) KEY256 Encryption)) where
  type Inverse (CGadget (Cipher (AES CBC) KEY256 Encryption)) = CGadget (Cipher (AES CBC) KEY256 Decryption)

instance HasInverse (CGadget (Cipher (AES CBC) KEY256 Decryption)) where
  type Inverse (CGadget (Cipher (AES CBC) KEY256 Decryption)) = CGadget (Cipher (AES CBC) KEY256 Encryption)