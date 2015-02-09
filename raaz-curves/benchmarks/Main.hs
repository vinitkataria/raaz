import           Data.Bits
import           Data.Version
import           Criterion.Main    (defaultMainWith)
import           Criterion         (bgroup)
import           Criterion.Config  (Config(..), ljust, defaultConfig)
import           Paths_raaz_curves (version)
import           System.Random

import           Raaz.Curves.P25519.Internal

import qualified EC25519.P25519 as P

pkgName = "raaz-curves-" ++ showVersion version

main :: IO ()
main = do
  gen <- newStdGen
  let (r1,gen1) = randomR (2, curve25519Q) gen
      (r2,gen2) = randomR (2, curve25519Q) gen1
  putStrLn $ "Running benchmarks for " ++ pkgName
  defaultMainWith defaultConfig (return ()) $ benchmarks (r1,r2)

benchmarks (r1,r2) = [ bgroup "Secret & PublicToken Generation" $ P.benchSecretPublic
                     , bgroup "Secret & PublicToken Generation with random provided" $ P.benchSecretPublicSameRandom r1
                     , bgroup "Shared Secret Generation with random provided" $ P.benchSharedSecret (r1,r2)
                     ]
