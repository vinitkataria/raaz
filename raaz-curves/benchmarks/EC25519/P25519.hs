module EC25519.P25519 ( benchSecretPublic
                      , benchSecretPublicSameRandom
                      , benchSharedSecret
                      ) where

import Criterion.Main
import Data.Bits
--import System.Random

import Raaz.Curves.EC25519.CPortable
import Raaz.Curves.P25519.Internal
import Raaz.Random

benchSPref :: IO (Secret25519, PublicToken25519)
benchSPref = do
  random <- getPseudoRandomP25519
  let secret = generateSecretEC25519 random
  return (secret, publicToken (undefined :: P25519) secret)

benchSPcport :: IO (Secret25519, PublicToken25519)
benchSPcport = do
  random <- getPseudoRandomP25519
  cGenerateParamsEC25519 random

benchSPgivenRandomRef :: Integer -> (Secret25519, PublicToken25519)
benchSPgivenRandomRef random = (secret, publicToken (undefined :: P25519) secret)
  where secret = generateSecretEC25519 (P25519 random)

benchSPgivenRandomCport :: Integer -> IO (Secret25519, PublicToken25519)
benchSPgivenRandomCport random = do
  cGenerateParamsEC25519 (P25519 random)

benchSSref :: (Integer,Integer) -> SharedSecret25519
benchSSref (r1,r2) = sharedSecret (undefined :: P25519) secret (PublicToken25519 (P25519 r2))
  where secret = generateSecretEC25519 (P25519 r1)

benchSScport :: (Integer,Integer) -> IO (SharedSecret25519)
benchSScport (r1,r2) = cCalculateSecretEC25519 (Secret25519 (P25519 r1)) (PublicToken25519 (P25519 r2))

benchSecretPublic :: [ Benchmark ]
benchSecretPublic = [ bench "Reference" $ whnfIO benchSPref
                    , bench "CPortable" $ whnfIO benchSPcport
                    ]

benchSecretPublicSameRandom :: Integer -> [ Benchmark ]
benchSecretPublicSameRandom r = [ bench "Reference" $ whnf benchSPgivenRandomRef r
                                , bench "CPortable" $ whnfIO (benchSPgivenRandomCport r)
                                ]

benchSharedSecret :: (Integer, Integer) -> [ Benchmark ]
benchSharedSecret pair = [ bench "Reference" $ whnf benchSSref pair
                         , bench "CPortable" $ whnfIO (benchSScport pair)
                         ]