{-# LANGUAGE OverloadedStrings #-}

import qualified Data.Map.Strict as Map
import Data.Function ((&))
import qualified SecretSpec as S

main :: IO ()
main = do
  resolved <-
    S.load
      ( S.builder
          & S.withProvider "keyring://"
          & S.withProfile "production"
          & S.withReason "boot web app"
      )

  print (S.resolvedProvider resolved, S.resolvedProfile resolved)
  case Map.lookup "DATABASE_URL" (S.resolvedSecrets resolved) of
    Just db -> print (S.get db) -- the value, or the file path for as_path secrets
    Nothing -> pure ()
  S.setAsEnv resolved           -- export everything into the process environment
  S.close resolved
