{- |

Types for Diffie Hellman key exchange.

It also includes the standard oakley groups defined in
<http://www.ietf.org/rfc/rfc2409.txt rfc2409> and
<http://www.ietf.org/rfc/rfc3526.txt rfc3526>.

-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Raaz.DH.Types
       (
         Group(..)
         -- * Oakley groups
       , oakley1
       , oakley2
       , oakley5
       , oakley14
       , oakley15
       , oakley16
       , oakley17
       , oakley18
         -- * DH Types
       , SharedSecret(..)
       , PublicNum(..)
       , PrivateNum(..)
       ) where

import Foreign.Storable
import Raaz.Number

-- | Group used in DH computation
data Group w = Group { prime     :: w -- ^ Large safe prime: p
                     , generator :: w -- ^ Generator: g
                     , order     :: w -- ^ Prime order: q
                     } deriving Show

-- | Oakley group 1 with 768 bit prime
oakley1 :: Group Word1024
oakley1 = Group { prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF
                , generator = 2
                , order = 0x7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68948127044533E63A0105DF531D89CD9128A5043CC71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122F242DABB312F3F637A262174D31D1B107FFFFFFFFFFFFFFF
                }

-- | Oakley group 2 with 1024 bit prime
oakley2 :: Group Word1024
oakley2 = Group { prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
                , generator = 2
                , order = 0x7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68948127044533E63A0105DF531D89CD9128A5043CC71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6F71C35FDAD44CFD2D74F9208BE258FF324943328F67329C0FFFFFFFFFFFFFFFF
                }


-- | Oakley group 5 with 1536 bit prime
oakley5 :: Group Word2048
oakley5 = Group { prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
                , generator = 2
                , order = 0x7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68948127044533E63A0105DF531D89CD9128A5043CC71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9EE1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD47E9267AFC1B2AE91EE51D6CB0E3179AB1042A95DCF6A9483B84B4B36B3861AA7255E4C0278BA36046511B993FFFFFFFFFFFFFFFF
                }

-- | Oakley group 14 with 2048 bit prime
oakley14 :: Group Word2048
oakley14 = Group { prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
                 , generator = 2
                 , order = 0x7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267afc1b2ae91ee51d6cb0e3179ab1042a95dcf6a9483b84b4b36b3861aa7255e4c0278ba3604650c10be19482f23171b671df1cf3b960c074301cd93c1d17603d147dae2aef837a62964ef15e5fb4aac0b8c1ccaa4be754ab5728ae9130c4c7d02880ab9472d455655347fffffffffffffff
                 }

-- | Oakley group 15 with 3072 bit prime
oakley15 :: Group Word4096
oakley15 = Group { prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
                 , generator = 2
                 , order = 0x7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267afc1b2ae91ee51d6cb0e3179ab1042a95dcf6a9483b84b4b36b3861aa7255e4c0278ba3604650c10be19482f23171b671df1cf3b960c074301cd93c1d17603d147dae2aef837a62964ef15e5fb4aac0b8c1ccaa4be754ab5728ae9130c4c7d02880ab9472d45556216d6998b8682283d19d42a90d5ef8e5d32767dc2822c6df785457538abae83063ed9cb87c2d370f263d5fad7466d8499eb8f464a702512b0cee771e9130d697735f897fd036cc504326c3b01399f643532290f958c0bbd90065df08babbd30aeb63b84c4605d6ca371047127d03a72d598a1edadfe707e884725c16890549d69657fffffffffffffff
                 }

-- | Oakley group 16 with 4096 bit prime
oakley16 :: Group Word4096
oakley16 = Group { prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF
                 , generator = 2
                 , order = 0x7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267afc1b2ae91ee51d6cb0e3179ab1042a95dcf6a9483b84b4b36b3861aa7255e4c0278ba3604650c10be19482f23171b671df1cf3b960c074301cd93c1d17603d147dae2aef837a62964ef15e5fb4aac0b8c1ccaa4be754ab5728ae9130c4c7d02880ab9472d45556216d6998b8682283d19d42a90d5ef8e5d32767dc2822c6df785457538abae83063ed9cb87c2d370f263d5fad7466d8499eb8f464a702512b0cee771e9130d697735f897fd036cc504326c3b01399f643532290f958c0bbd90065df08babbd30aeb63b84c4605d6ca371047127d03a72d598a1edadfe707e884725c16890549084008d391e0953c3f36bc438cd085edd2d934ce1938c357a711e0d4a341a5b0a85ed12c1f4e5156a26746ddde16d826f477c97477e0a0fdf6553143e2ca3a735e02eccd94b27d04861d1119dd0c328adf3f68fb094b867716bd7dc0deebb10b8240e68034893ead82d54c9da754c46c7eee0c37fdbee48536047a6fa1ae49a0318ccffffffffffffffff
                 }

-- | Oakley group 17 with 6144 bit prime
oakley17 :: Group Word8192
oakley17 = Group { prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF
                 , generator = 2
                 , order = 0x7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267afc1b2ae91ee51d6cb0e3179ab1042a95dcf6a9483b84b4b36b3861aa7255e4c0278ba3604650c10be19482f23171b671df1cf3b960c074301cd93c1d17603d147dae2aef837a62964ef15e5fb4aac0b8c1ccaa4be754ab5728ae9130c4c7d02880ab9472d45556216d6998b8682283d19d42a90d5ef8e5d32767dc2822c6df785457538abae83063ed9cb87c2d370f263d5fad7466d8499eb8f464a702512b0cee771e9130d697735f897fd036cc504326c3b01399f643532290f958c0bbd90065df08babbd30aeb63b84c4605d6ca371047127d03a72d598a1edadfe707e884725c16890549084008d391e0953c3f36bc438cd085edd2d934ce1938c357a711e0d4a341a5b0a85ed12c1f4e5156a26746ddde16d826f477c97477e0a0fdf6553143e2ca3a735e02eccd94b27d04861d1119dd0c328adf3f68fb094b867716bd7dc0deebb10b8240e68034893ead82d54c9da754c46c7eee0c37fdbee48536047a6fa1ae49a0142491b61fd5a693e381360ea6e593013236f64ba8f3b1edd1bdefc7fca0356cf298772ed9c17a09800d7583529f6c813ec188bcb93d8432d448c6d1f6df5e7cd8a76a267365d676a5d8dedbf8a23f36612a5999028a895ebd7a137dc7a009bc6695facc1e500e325c9767819750ae8b90e81fa416be7373a7f7b6aaf3817a34c06415ad42018c8058e4f2cf3e4bfdf63f47991d4bd3f1b66445f078ea2dbffac2d62a5ea03d915a0aa556647b6bf5fa470ec0a662f6907c01bf053cb8af7794df1940350eac5dbe2ed3b7aa8551ec50fdff8758ce658d189eaae6d2b64f617794b191c3ff46bb71e0234021f47b31fa43077095f96ad85ba3a6b734a7c8f36e620127fffffffffffffff
                 }

-- | Oakley group 18 with 8192 bit prime
oakley18 :: Group Word8192
oakley18 = Group { prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF
                 , generator = 2
                 , order = 0x7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267afc1b2ae91ee51d6cb0e3179ab1042a95dcf6a9483b84b4b36b3861aa7255e4c0278ba3604650c10be19482f23171b671df1cf3b960c074301cd93c1d17603d147dae2aef837a62964ef15e5fb4aac0b8c1ccaa4be754ab5728ae9130c4c7d02880ab9472d45556216d6998b8682283d19d42a90d5ef8e5d32767dc2822c6df785457538abae83063ed9cb87c2d370f263d5fad7466d8499eb8f464a702512b0cee771e9130d697735f897fd036cc504326c3b01399f643532290f958c0bbd90065df08babbd30aeb63b84c4605d6ca371047127d03a72d598a1edadfe707e884725c16890549084008d391e0953c3f36bc438cd085edd2d934ce1938c357a711e0d4a341a5b0a85ed12c1f4e5156a26746ddde16d826f477c97477e0a0fdf6553143e2ca3a735e02eccd94b27d04861d1119dd0c328adf3f68fb094b867716bd7dc0deebb10b8240e68034893ead82d54c9da754c46c7eee0c37fdbee48536047a6fa1ae49a0142491b61fd5a693e381360ea6e593013236f64ba8f3b1edd1bdefc7fca0356cf298772ed9c17a09800d7583529f6c813ec188bcb93d8432d448c6d1f6df5e7cd8a76a267365d676a5d8dedbf8a23f36612a5999028a895ebd7a137dc7a009bc6695facc1e500e325c9767819750ae8b90e81fa416be7373a7f7b6aaf3817a34c06415ad42018c8058e4f2cf3e4bfdf63f47991d4bd3f1b66445f078ea2dbffac2d62a5ea03d915a0aa556647b6bf5fa470ec0a662f6907c01bf053cb8af7794df1940350eac5dbe2ed3b7aa8551ec50fdff8758ce658d189eaae6d2b64f617794b191c3ff46bb71e0234021f47b31fa43077095f96ad85ba3a6b734a7c8f36df08acba51c937897f72f21c3bbe5b54996fc66c5f626839dc98dd1de4195b46cee9803a0fd3dfc57e23f692bb7b49b5d212331d55b1ce2d727ab41a11da3a15f8e4bc11c78b65f1ceb296f1fedc5f7e42456c911117025201be0389f5abd40d11f8639a39fe3236751835a5e5e44317c1c2eefd4ea5bfd16043f43cb41981f6adee9d03159e7ad9d13c53369509fc1fa27c16ef9887703a55b51b22cbf44cd012aee0b2798e628423428efcd5a40caef6bf50d8ea885ebf73a6b9fd79b5e18f67d1341ac8237a75c3cfc92004a1c5a40e366bc44d00176af71c15e48c86d37e013723caac7223ab3bf4d54f1828713b2b4a6fe40fab74405cb738b064c06ecc76e9efffffffffffffffff
                 }

-- | Shared Secret
newtype SharedSecret w = SharedSecret w
                       deriving (Show, Eq, Ord, Num, Integral, Storable, Modular, Real, Enum)

-- | Public key
newtype PublicNum w = PublicNum w
                    deriving (Show, Eq, Ord, Num, Integral, Storable, Modular, Real, Enum)

-- | Private key
newtype PrivateNum w = PrivateNum w
                    deriving (Show, Eq, Ord, Num, Integral, Storable, Modular, Real, Enum)
