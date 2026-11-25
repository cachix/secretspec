{-# LANGUAGE OverloadedStrings #-}

import Data.Function ((&))
import qualified SecretSpec as S

main :: IO ()
main = do
  resolved <- S.load (S.builder & S.withScope "api")
  S.close resolved
