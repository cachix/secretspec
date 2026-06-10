{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Haskell SDK for SecretSpec, a declarative secrets manager.
--
-- A thin client over the @secretspec-ffi@ C ABI, linked at build time.
-- Resolution (providers, fallback chains, profiles, generation, @as_path@)
-- happens entirely in the Rust core; this module marshals a JSON request to
-- @secretspec_resolve@, parses the response envelope, and exposes it with the
-- same vocabulary as the Rust derive crate.
--
-- > import qualified SecretSpec as S
-- > import Data.Function ((&))
-- >
-- > main = do
-- >   resolved <- S.load (S.builder & S.withProvider "keyring://" & S.withReason "boot")
-- >   print (S.get =<< Data.Map.lookup "DATABASE_URL" (S.resolvedSecrets resolved))
-- >   S.setAsEnv resolved
module SecretSpec
  ( -- * Builder
    Builder
  , builder
  , withPath
  , withProvider
  , withProfile
  , withReason
  , withNoValues
    -- * Resolve (value-carrying)
  , Resolved(..)
  , ResolvedSecret(..)
  , load
  , get
  , fields
  , fieldsJson
  , setAsEnv
  , close
    -- * Report (value-free)
  , Report(..)
  , SecretReport(..)
  , report
    -- * Errors
  , SecretSpecError(..)
  , MissingRequiredError(..)
    -- * Misc
  , abiVersion
  ) where

import           Control.Exception (Exception, throwIO)
import           Control.Monad (forM_, unless, when)
import           Data.Aeson (FromJSON (..), Value, eitherDecodeStrict, encode,
                             object, withObject, (.!=), (.:), (.:?), (.=))
import           Data.Aeson.Types (parseEither)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import           Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import           Data.Maybe (catMaybes)
import           Data.Text (Text)
import qualified Data.Text as T
import           Foreign.C.String (CString, peekCString)
import           Foreign.Ptr (nullPtr)
import           System.Directory (doesFileExist, removeFile)
import           System.Environment (setEnv)

-- The three C ABI functions, linked at build time (-lsecretspec_ffi). They are
-- declared @safe@ because @secretspec_resolve@ may block on provider I/O
-- (1Password, LastPass), and a @safe@ call lets other Haskell threads run.
foreign import ccall safe "secretspec_resolve"
  c_secretspec_resolve :: CString -> IO CString

foreign import ccall safe "secretspec_free"
  c_secretspec_free :: CString -> IO ()

foreign import ccall safe "secretspec_abi_version"
  c_secretspec_abi_version :: IO CString

-- | Wire-format version of the value-carrying resolve response this SDK
-- understands. Tracks @secretspec@'s @RESOLVE_SCHEMA_VERSION@.
resolveSchemaVersion :: Int
resolveSchemaVersion = 1

-- | Wire-format version of the value-free report. Tracks @secretspec@'s
-- @RESOLUTION_REPORT_SCHEMA_VERSION@.
reportSchemaVersion :: Int
reportSchemaVersion = 1

-- | A resolution failure (bad manifest, provider error, reason policy). Carries
-- a stable @kind@.
data SecretSpecError = SecretSpecError
  { errorKind    :: Text
  , errorMessage :: Text
  } deriving (Show, Eq)

instance Exception SecretSpecError

-- | One or more required secrets were not found anywhere.
newtype MissingRequiredError = MissingRequiredError
  { missing :: [Text]
  } deriving (Show, Eq)

instance Exception MissingRequiredError

-- | One resolved secret. Exactly one of 'secretValue' \/ 'secretPath' is set:
-- the path for @as_path@ secrets, the value otherwise. Both are 'Nothing' for a
-- value-less ('withNoValues') response.
data ResolvedSecret = ResolvedSecret
  { secretValue          :: Maybe Text
  , secretPath           :: Maybe Text
  , secretAsPath         :: Bool
  , secretSource         :: Text
  , secretSourceProvider :: Maybe Text
  } deriving (Show, Eq)

instance FromJSON ResolvedSecret where
  parseJSON = withObject "ResolvedSecret" $ \o ->
    ResolvedSecret
      <$> o .:? "value"
      <*> o .:? "path"
      <*> o .:? "as_path" .!= False
      <*> o .: "source"
      <*> o .:? "source_provider"

-- | A successful resolution, mirroring the Rust @Resolved@ wrapper.
data Resolved = Resolved
  { resolvedProvider        :: Text
  , resolvedProfile         :: Text
  , resolvedSecrets         :: Map Text ResolvedSecret
  , resolvedMissingOptional :: [Text]
  } deriving (Show, Eq)

-- | The value-free resolution outcome for one declared secret: how it would
-- resolve and from where, never the value itself.
data SecretReport = SecretReport
  { srName           :: Text
  , srStatus         :: Text -- ^ @"resolved"@, @"missing_required"@, or @"missing_optional"@.
  , srRequired       :: Bool
  , srSourceProvider :: Maybe Text
  , srDefaultApplied :: Bool
  , srGenerated      :: Bool
  , srAsPath         :: Bool
  } deriving (Show, Eq)

instance FromJSON SecretReport where
  parseJSON = withObject "SecretReport" $ \o ->
    SecretReport
      <$> o .: "name"
      <*> o .: "status"
      <*> o .:? "required" .!= False
      <*> o .:? "source_provider"
      <*> o .:? "default_applied" .!= False
      <*> o .:? "generated" .!= False
      <*> o .:? "as_path" .!= False

-- | A value-free resolution snapshot. Unlike 'Resolved', a missing required
-- secret is a @"missing_required"@ status here, not an error.
data Report = Report
  { reportProvider :: Text
  , reportProfile  :: Text
  , reportSecrets  :: [SecretReport]
  } deriving (Show, Eq)

-- | A resolution request. Build it from 'builder' with the @withX@ setters and
-- pass it to 'load' or 'report'.
data Builder = Builder
  { bPath     :: Maybe Text
  , bProvider :: Maybe Text
  , bProfile  :: Maybe Text
  , bReason   :: Maybe Text
  , bNoValues :: Bool
  }

-- | A builder with no options set.
builder :: Builder
builder = Builder Nothing Nothing Nothing Nothing False

-- | Resolve from a manifest at this path instead of walking up from the working
-- directory.
withPath :: Text -> Builder -> Builder
withPath v b = b { bPath = Just v }

-- | Override the provider (a @keyring:\/\/@-style URI or a configured alias).
withProvider :: Text -> Builder -> Builder
withProvider v b = b { bProvider = Just v }

-- | Override the profile.
withProfile :: Text -> Builder -> Builder
withProfile v b = b { bProfile = Just v }

-- | Set a human-readable reason for this access (for audited providers).
withReason :: Text -> Builder -> Builder
withReason v b = b { bReason = Just v }

-- | Omit secret values, returning only structure and provenance.
withNoValues :: Bool -> Builder -> Builder
withNoValues v b = b { bNoValues = v }

-- | The usable string: the file path for @as_path@ secrets, else the value.
-- 'Nothing' when no usable value is present (e.g. under 'withNoValues').
get :: ResolvedSecret -> Maybe Text
get s = if secretAsPath s then secretPath s else secretValue s

-- | Flat @name -> usable value@ map ('Nothing' encodes to JSON @null@), the
-- input for a quicktype-generated deserializer. See @secretspec schema@.
fields :: Resolved -> Map Text (Maybe Text)
fields = Map.map get . resolvedSecrets

-- | 'fields' as a JSON byte string (a @{SECRET_NAME: value-or-null}@ object).
fieldsJson :: Resolved -> BL.ByteString
fieldsJson = encode . fields

-- | Export each resolved secret into the process environment by its declared
-- name. Secrets with no usable value (e.g. under 'withNoValues') are skipped.
setAsEnv :: Resolved -> IO ()
setAsEnv r =
  forM_ (Map.toList (resolvedSecrets r)) $ \(name, secret) ->
    case get secret of
      Just v  -> setEnv (T.unpack name) (T.unpack v)
      Nothing -> pure ()

-- | Remove the temp files backing any @as_path@ secrets in this result. The
-- resolver persists those files (mode 0400) so their paths stay valid after
-- resolve returns; the caller owns their lifetime. Call 'close' when done so the
-- secret files do not accumulate in the temp dir. A file already gone is ignored.
close :: Resolved -> IO ()
close r =
  forM_ (Map.elems (resolvedSecrets r)) $ \secret ->
    case (secretAsPath secret, secretPath secret) of
      (True, Just p) -> do
        let fp = T.unpack p
        exists <- doesFileExist fp
        when exists (removeFile fp)
      _ -> pure ()

-- | The ABI version reported by the loaded native library.
abiVersion :: IO Text
abiVersion = do
  -- A static, library-owned string; do not free it.
  c <- c_secretspec_abi_version
  T.pack <$> peekCString c

-- | Resolve the secrets. Throws 'MissingRequiredError' if a required secret is
-- missing, and 'SecretSpecError' for any other failure.
load :: Builder -> IO Resolved
load b = do
  resp <- callNative (requestBytes b Nothing)
  value <- responseValue resp resolveSchemaVersion "resolve"
  (prov, prof, secs, mreq, mopt) <- fromResult (parseEither pResolve value)
  case mreq of
    [] -> pure (Resolved prov prof secs mopt)
    xs -> throwIO (MissingRequiredError xs)
  where
    pResolve = withObject "response" $ \o ->
      (,,,,)
        <$> o .: "provider"
        <*> o .: "profile"
        <*> o .:? "secrets" .!= Map.empty
        <*> o .:? "missing_required" .!= []
        <*> o .:? "missing_optional" .!= []

-- | Resolve a value-free 'Report' (the inventory\/preflight view, the same one
-- the CLI exposes as @check --json@). Unlike 'load', it does not throw when a
-- required secret is missing: that secret appears as a 'SecretReport' with
-- status @"missing_required"@.
report :: Builder -> IO Report
report b = do
  resp <- callNative (requestBytes b (Just "report"))
  value <- responseValue resp reportSchemaVersion "report"
  (prov, prof, secs) <- fromResult (parseEither pReport value)
  pure (Report prov prof secs)
  where
    pReport = withObject "response" $ \o ->
      (,,)
        <$> o .: "provider"
        <*> o .: "profile"
        <*> o .:? "secrets" .!= []

-- Build the request JSON for a resolve (@mode = Nothing@) or report
-- (@mode = Just "report"@), omitting unset options.
requestBytes :: Builder -> Maybe Text -> BL.ByteString
requestBytes b mode =
  encode . object $
    catMaybes
      [ ("path" .=) <$> bPath b
      , ("provider" .=) <$> bProvider b
      , ("profile" .=) <$> bProfile b
      , ("reason" .=) <$> bReason b
      ]
      ++ ["no_values" .= True | bNoValues b]
      ++ ["mode" .= m | Just m <- [mode]]

-- Marshal a request to secretspec_resolve and copy the response out before
-- freeing the native allocation.
callNative :: BL.ByteString -> IO BS.ByteString
callNative reqLazy =
  BS.useAsCString (BL.toStrict reqLazy) $ \creq -> do
    cresp <- c_secretspec_resolve creq
    if cresp == nullPtr
      then throwIO (SecretSpecError "ffi" "secretspec_resolve returned null")
      else do
        resp <- BS.packCString cresp
        c_secretspec_free cresp
        pure resp

-- Decode the envelope, unwrap @ok@/@error@, and check the schema version,
-- returning the response object as a 'Value' for the caller to project.
responseValue :: BS.ByteString -> Int -> Text -> IO Value
responseValue resp expectVer kind = do
  env <- case eitherDecodeStrict resp :: Either String (Envelope Value) of
    Left e  -> throwIO (SecretSpecError "parse" (T.pack e))
    Right v -> pure v
  if not (envOk env)
    then case envError env of
      Just (ErrInfo k m) -> throwIO (SecretSpecError k m)
      Nothing            -> throwIO (SecretSpecError "unknown" "")
    else case envResponse env of
      Nothing -> throwIO (SecretSpecError "ffi" "secretspec_resolve reported ok with no response")
      Just value -> do
        ver <- fromResult (parseEither (withObject "response" (.: "schema_version")) value)
        unless (ver == expectVer) (throwIO (versionError ver expectVer kind))
        pure value

versionError :: Int -> Int -> Text -> SecretSpecError
versionError got expected kind =
  SecretSpecError "version" $
    T.concat
      [ "unsupported ", kind, " schema version ", T.pack (show got)
      , " (expected ", T.pack (show expected)
      , "); the secretspec-ffi library and this SDK are out of sync"
      ]

fromResult :: Either String a -> IO a
fromResult = either (throwIO . SecretSpecError "parse" . T.pack) pure

-- The response envelope shared by every native binding.
data Envelope a = Envelope
  { envOk       :: Bool
  , envResponse :: Maybe a
  , envError    :: Maybe ErrInfo
  }

instance FromJSON a => FromJSON (Envelope a) where
  parseJSON = withObject "Envelope" $ \o ->
    Envelope <$> o .: "ok" <*> o .:? "response" <*> o .:? "error"

data ErrInfo = ErrInfo Text Text

instance FromJSON ErrInfo where
  parseJSON = withObject "error" $ \o -> ErrInfo <$> o .: "kind" <*> o .: "message"
