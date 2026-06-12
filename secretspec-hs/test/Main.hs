{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Unit + cross-language conformance tests for the Haskell SDK. Run with the
-- cdylib on the linker and loader paths:
--
-- > cabal test --extra-lib-dirs="$TARGET/debug"   # with LD_LIBRARY_PATH set
module Main (main) where

import           Control.Exception (SomeException, try)
import           Control.Monad (filterM, forM)
import           Data.Aeson (Value, eitherDecode, eitherDecodeStrict, object,
                             (.=))
import qualified Data.Aeson.Key as Key
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import           Data.Function ((&))
import           Data.List (isInfixOf, isPrefixOf, sort)
import qualified Data.Map.Strict as Map
import           Data.Maybe (fromMaybe, isJust)
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import qualified SecretSpec as S
import           System.Directory (canonicalizePath, createDirectoryIfMissing,
                                   doesDirectoryExist, findExecutable,
                                   getTemporaryDirectory, listDirectory)
import           System.Environment (lookupEnv)
import           System.Exit (exitFailure, exitSuccess)
import           System.FilePath ((</>))
import           System.Process (callProcess, readProcess)

main :: IO ()
main = do
  fixturesDir <- canonicalizePath ("." </> ".." </> "conformance" </> "fixtures")
  names <- listDirectory fixturesDir
  fixtures <- filterM doesDirectoryExist (map (fixturesDir </>) (sort names))

  let tests =
        [ ("abi_version_nonempty", testAbiVersion)
        , ("missing_required_throws", testMissingRequired)
        , ("codegen", testCodegen)
        ]
          ++ concatMap conformanceTests fixtures

  results <- mapM runOne tests
  let failed = [name | (name, ok) <- results, not ok]
  putStrLn ""
  putStrLn (show (length results - length failed) ++ "/" ++ show (length results) ++ " passed")
  if null failed
    then exitSuccess
    else putStrLn ("FAILED: " ++ unwords failed) >> exitFailure

runOne :: (String, IO ()) -> IO (String, Bool)
runOne (name, act) = do
  r <- try act :: IO (Either SomeException ())
  case r of
    Right () -> putStrLn ("ok   " ++ name) >> pure (name, True)
    Left e   -> putStrLn ("FAIL " ++ name ++ ": " ++ show e) >> pure (name, False)

expect :: Bool -> String -> IO ()
expect True _    = pure ()
expect False msg = ioError (userError msg)

-- Unit tests --------------------------------------------------------------

testAbiVersion :: IO ()
testAbiVersion = do
  v <- S.abiVersion
  expect (not (T.null v)) "abi version was empty"

testMissingRequired :: IO ()
testMissingRequired = do
  tmp <- getTemporaryDirectory
  let dir = tmp </> "secretspec-hs-missing"
  createDirectoryIfMissing True dir
  writeFile (dir </> "secretspec.toml") $
    unlines
      [ "[project]"
      , "name = \"hs-missing\""
      , "revision = \"1.0\""
      , ""
      , "[profiles.default]"
      , "NEEDED = { description = \"x\", required = true }"
      ]
  writeFile (dir </> ".env") ""
  r <-
    try (S.load (fixtureBuilder dir)) ::
      IO (Either S.MissingRequiredError S.Resolved)
  case r of
    Left _  -> pure ()
    Right _ -> ioError (userError "expected MissingRequiredError")

-- End-to-end codegen: secretspec schema -> quicktype --lang haskell -> compile
-- the generated module and decode the SDK's own fieldsJson output with it, so
-- the schema -> fields() linkage is exercised, not just hand-written JSON. Skips
-- unless SECRETSPEC_BIN, npx, runghc, and a cabal-written GHC environment file
-- (so runghc sees aeson and the generated module's transitive imports) are all
-- present -- i.e. when run via `cabal test --write-ghc-environment-files=always`
-- with SECRETSPEC_BIN set, as scripts/ci-sdks.sh does.
testCodegen :: IO ()
testCodegen = do
  mbin <- lookupEnv "SECRETSPEC_BIN"
  npx <- findExecutable "npx"
  rghc <- findExecutable "runghc"
  hasEnv <- any (isPrefixOf ".ghc.environment.") <$> listDirectory "."
  case (mbin, npx, rghc, hasEnv) of
    (Just bin, Just _, Just _, True) -> runCodegen bin
    _ -> putStrLn "  (skipped: needs SECRETSPEC_BIN, npx, runghc, and a ghc env file)"

runCodegen :: FilePath -> IO ()
runCodegen bin = do
  tmp <- getTemporaryDirectory
  let dir = tmp </> "secretspec-hs-codegen"
  createDirectoryIfMissing True dir
  writeFile (dir </> "secretspec.toml") $
    unlines
      [ "[project]"
      , "name = \"hs-codegen\""
      , "revision = \"1.0\""
      , ""
      , "[profiles.default]"
      , "DATABASE_URL = { required = true }"
      , "LOG_LEVEL = { required = false, default = \"info\" }"
      ]
  writeFile (dir </> ".env") "DATABASE_URL=postgres://db\n"

  -- The SDK itself produces the flat fields JSON the generated decoder consumes,
  -- so this exercises the real schema -> fields() linkage.
  resolved <-
    S.load
      ( S.builder
          & S.withPath (T.pack (dir </> "secretspec.toml"))
          & S.withProvider (T.pack ("dotenv://" ++ (dir </> ".env")))
          & S.withReason "codegen"
      )
  BL.writeFile (dir </> "fields.json") (S.fieldsJson resolved)

  callProcess bin ["-f", dir </> "secretspec.toml", "schema", "-o", dir </> "schema.json"]
  callProcess
    "npx"
    [ "--yes", "quicktype", "-s", "schema", dir </> "schema.json"
    , "--top-level", "SecretSpec", "--lang", "haskell"
    , "--module", "Secrets", "-o", dir </> "Secrets.hs"
    ]
  writeFile (dir </> "Driver.hs") driverSource

  out <- readProcess "runghc" ["-i" ++ dir, dir </> "Driver.hs", dir </> "fields.json"] ""
  expect ("codegen OK" `isInfixOf` out) ("unexpected driver output: " ++ out)

-- A standalone program that decodes the SDK's fields JSON with the
-- quicktype-generated SecretSpec type, proving the generated code is usable.
driverSource :: String
driverSource =
  unlines
    [ "{-# LANGUAGE OverloadedStrings #-}"
    , "import Secrets (SecretSpec(..), decodeTopLevel)"
    , "import qualified Data.ByteString.Lazy as BL"
    , "import System.Environment (getArgs)"
    , "import System.Exit (exitFailure)"
    , "main :: IO ()"
    , "main = do"
    , "  [f] <- getArgs"
    , "  bytes <- BL.readFile f"
    , "  case decodeTopLevel bytes of"
    , "    Just s | databaseURLSecretSpec s == \"postgres://db\" -> putStrLn \"codegen OK\""
    , "    _ -> exitFailure"
    ]

-- Conformance -------------------------------------------------------------

conformanceTests :: FilePath -> [(String, IO ())]
conformanceTests dir =
  [ ("conformance:" ++ base, testConformance dir)
  , ("conformance_no_values:" ++ base, testNoValues dir)
  , ("conformance_report:" ++ base, testReport dir)
  ]
  where
    base = lastSegment dir

testConformance :: FilePath -> IO ()
testConformance dir = do
  resolved <- S.load (fixtureBuilder dir)
  actual <- canonical resolved
  expected <- readJson (dir </> "expected.json")
  expect (actual == expected) (mismatch "expected.json" actual expected)
  -- Remove any as_path temp files this value-carrying resolve materialized, so
  -- repeated runs do not leave secret-bearing files behind in the temp dir.
  S.close resolved

-- Under no_values every SDK must emit the same all-null fields map: a
-- value-less secret serializes to null, not an empty string.
testNoValues :: FilePath -> IO ()
testNoValues dir = do
  resolved <- S.load (S.withNoValues True (fixtureBuilder dir))
  let actual = either error id (eitherDecode (S.fieldsJson resolved)) :: Value
  expected <- readJson (dir </> "expected_no_values.json")
  expect (actual == expected) (mismatch "expected_no_values.json" actual expected)
  S.close resolved

-- The value-free report (status + provenance) is identical across SDKs.
testReport :: FilePath -> IO ()
testReport dir = do
  rep <- S.report (fixtureBuilder dir)
  let actual = canonicalReport rep
  expected <- readJson (dir </> "expected_report.json")
  expect (actual == expected) (mismatch "expected_report.json" actual expected)

fixtureBuilder :: FilePath -> S.Builder
fixtureBuilder dir =
  S.builder
    & S.withPath (T.pack (dir </> "secretspec.toml"))
    & S.withProvider (T.pack ("dotenv://" ++ (dir </> ".env")))
    & S.withReason "conformance"

canonical :: S.Resolved -> IO Value
canonical r = do
  entries <-
    forM (Map.toList (S.resolvedSecrets r)) $ \(name, secret) -> do
      value <-
        if S.secretAsPath secret
          then TIO.readFile (T.unpack (fromMaybe "" (S.secretPath secret)))
          else pure (fromMaybe "" (S.secretValue secret))
      pure
        ( Key.fromText name
            .= object
              [ "value" .= value
              , "source" .= S.secretSource secret
              , "as_path" .= S.secretAsPath secret
              ]
        )
  pure $
    object
      [ "profile" .= S.resolvedProfile r
      , "secrets" .= object entries
      , "missing_required" .= ([] :: [Text])
      , "missing_optional" .= sort (S.resolvedMissingOptional r)
      ]

canonicalReport :: S.Report -> Value
canonicalReport rep =
  object
    [ "profile" .= S.reportProfile rep
    , "secrets"
        .= object
          [ Key.fromText (S.srName s)
              .= object
                [ "status" .= S.srStatus s
                , "required" .= S.srRequired s
                , "as_path" .= S.srAsPath s
                , "generated" .= S.srGenerated s
                , "default_applied" .= S.srDefaultApplied s
                , -- Present-or-not (not the path-dependent value) so the vector
                  -- is machine-independent yet still catches a dropped provider.
                  "source_provider" .= isJust (S.srSourceProvider s)
                ]
          | s <- S.reportSecrets rep
          ]
    ]

readJson :: FilePath -> IO Value
readJson p = do
  bytes <- BS.readFile p
  either (ioError . userError) pure (eitherDecodeStrict bytes)

mismatch :: String -> Value -> Value -> String
mismatch name actual expected =
  name ++ " mismatch\n got: " ++ show actual ++ "\nwant: " ++ show expected

lastSegment :: FilePath -> String
lastSegment = reverse . takeWhile (/= '/') . reverse
