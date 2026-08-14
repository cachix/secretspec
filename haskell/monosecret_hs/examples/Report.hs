{-# LANGUAGE OverloadedStrings #-}

import Data.Function ((&))
import qualified Monosecret as S

main :: IO ()
main = do
  rep <- S.report (S.builder & S.withProfile "production")
  mapM_ (\s -> print (S.srName s, S.srStatus s, S.srRequired s)) (S.reportSecrets rep)
