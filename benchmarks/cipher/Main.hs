import           Data.Version
import           Criterion.Main          (defaultMainWith)
import           Criterion               (bgroup)
import           Criterion.Main.Options
import           Paths_src               (version)

import qualified Modules.AES       as AES
import qualified Modules.Salsa20   as S20

import           Modules.Defaults

pkgName = "raaz-cipher-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running benchmarks for " ++ pkgName
          putStrLn $ "Data Size : " ++ show nSize
          b <- benchmarks
          defaultMainWith defaultConfig b

benchmarksTiny = do
  aes <- AES.benchmarksTiny
  salsa <- S20.benchmarksTiny
  return [bgroup "AES" aes, bgroup "Salsa20" salsa]

benchmarks= do
  aes <- AES.benchmarks
  salsa <- S20.benchmarks
  return [bgroup "AES" aes, bgroup "Salsa20" salsa]
