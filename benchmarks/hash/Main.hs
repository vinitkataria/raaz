import           Data.Version
import           Criterion.Main          (defaultMainWith)
import           Criterion               (bgroup)
import           Criterion.Main.Options
import           Paths_src               (version)

import qualified Modules.Sha       as Sha
import qualified Modules.Blake     as Blake

import           Modules.Defaults

pkgName = "raaz-hash-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running benchmarks for " ++ pkgName
          putStrLn $ "Data Size : " ++ show nSize
          b <- benchmarks
          defaultMainWith defaultConfig b

benchmarks = do
  sha <- Sha.benchmarks
  blake <- Blake.benchmarks
  return [ bgroup "SHA" sha
         , bgroup "BLAKE" blake
         ]
