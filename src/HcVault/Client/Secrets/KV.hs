{-# LANGUAGE TemplateHaskell #-}
module HcVault.Client.Secrets.KV
  ( -- * Storing secrets
    putSecretAt
  , putSecret
  , patchSecretAt
  , patchSecret
    -- * Storing secrets with CAS
  , putSecretCasAt
  , putSecretCas
  , patchSecretCasAt
  , patchSecretCas
    -- * Reading secrets
  , readSecretAt
  , readSecret
  , readSecretVersionAt
  , readSecretVersion
    -- * Deleting secrets
  , deleteSecretAt
  , deleteSecret
  , deleteSecretVersionsAt
  , deleteSecretVersions
  , undeleteSecretVersionsAt
  , undeleteSecretVersions
  , destroySecretVersionsAt
  , destroySecretVersions
    -- * Metadata
  , listSecretsAt
  , listSecrets
  , readSecretMetadata
  , readSecretMetadataAt
  , putSecretMetadataAt
  , putSecretMetadata
  , deleteSecretMetadataAt
  , deleteSecretMetadata
    -- * Configuring
  , readKvEngineConfigAt
  , readKvEngineConfig
  , putKvEngineConfigAt
  , putKvEngineConfig
  , KvEngineConfig(..)
    -- * Types
  , KvKey(..)
  , KvPath(..)
  , appendKvPath
  , KvValue
  , KvSecret
  , KvVersion(..)
  , KvCustomMetadata
  , KvMetadata(..)
  , KvSecretMetadataConfig(..)
  , mkKvSecretMetadataConfig
  , KvSecretMetadata(..)
  , KvVersionInfo(..)
  ) where

import           Data.Aeson
    (FromJSON (..), FromJSONKey (..), ToJSON, Value (..), pairs, withObject,
    withText, (.:), (.:?), (.=))
import           Data.Aeson.Encoding (encodingToLazyByteString, pair)
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Map.Strict as Map
import           Data.String (IsString (..))
import           Data.Text (Text)
import qualified Data.Text as Text
import           Data.Time (UTCTime)
import           GHC.Generics (Generic)
import           HcVault.Client.Core

data KvKey
  = KvDir Text
  | KvKey Text
  deriving stock (Show, Eq, Ord)

instance FromJSON KvKey where
  parseJSON = withText "KvKey" $ \t ->
    pure $ if | Text.null t        -> KvKey t
              | Text.last t == '/' -> KvDir (Text.dropEnd 1 t)
              | otherwise          -> KvKey t

newtype KvPath = KvPath
  { unKvPath :: [Text] }
  deriving stock (Show, Eq, Ord)
  deriving newtype (Semigroup, Monoid)

instance IsString KvPath where
  fromString = KvPath . Text.splitOn "," . Text.strip . Text.pack . fromString

appendKvPath :: KvPath -> KvKey -> KvPath
appendKvPath (KvPath ps) k = KvPath $ case k of
  KvDir d -> ps <> [d]
  KvKey d -> ps <> [d]

newtype KvVersion = KvVersion
  { unKvVersion :: Int }
  deriving stock (Show, Eq, Ord)
  deriving newtype (FromJSON, ToJSON, FromJSONKey)

type KvValue = Map.Map Text Value

type KvCustomMetadata = Map.Map Text Text

data KvMetadata = KvMetadata
  { created_time    :: !UTCTime
  , deletion_time   :: !(Maybe UTCTime)
  , destroyed       :: !Bool
  , version         :: !KvVersion
  , custom_metadata :: !(Maybe KvCustomMetadata)
  } deriving stock (Eq, Ord, Show, Generic)

instance FromJSON KvMetadata where
  parseJSON = withObject "KvMetadata" $ \o -> do
    created_time  <- o .: "created_time"
    deletion_time <- (o .:? "deletion_time") >>= maybe (pure Nothing) mbTime
    destroyed     <- o .: "destroyed"
    version       <- o .: "version"
    custom_metadata <- o .:? "custom_metadata"
    pure KvMetadata{..}
    where
      mbTime (String t)
        | Text.null t = pure Nothing
      mbTime o = Just <$> parseJSON o

encodeSecrets :: KvValue -> LBS.ByteString
encodeSecrets v = encodingToLazyByteString $
  pairs $ "data" .= v

encodeSecretsCas :: KvVersion -> KvValue-> LBS.ByteString
encodeSecretsCas c v = encodingToLazyByteString $
  pairs $ "data" .= v <> (pair "options" . pairs $ "cas" .= c)


secretPath :: MountPoint -> KvPath -> [Text]
secretPath mp path =
  "v1":unMountPoint mp:"data": unKvPath path

setSecret
  :: ByteString
  -> MountPoint
  -> KvPath
  -> Maybe LBS.ByteString
  -> VaultRequest a
setSecret method mp path =
  mkVaultRequest method
  (secretPath mp path)

putSecretAt
  :: MountPoint
  -> KvPath
  -> KvValue
  -> VaultRequest KvMetadata
putSecretAt mp path =
  setSecret methodPost mp path . Just . encodeSecrets

-- | This endpoint creates a new version of a secret at the specified location.
putSecret :: KvPath -> KvValue -> VaultRequest KvMetadata
putSecret = putSecretAt "secret"

putSecretCasAt
  :: MountPoint
  -> KvPath
  -> KvVersion
  -> KvValue
  -> VaultRequest KvMetadata
putSecretCasAt mp path v =
  setSecret methodPost mp path . Just . encodeSecretsCas v

-- | This endpoint creates a new version of a secret at the specified location,
-- if current version matches the one provided.
putSecretCas
  :: KvPath
  -> KvVersion
  -> KvValue
  -> VaultRequest KvMetadata
putSecretCas = putSecretCasAt "secret"

patchSecretAt
  :: MountPoint
  -> KvPath
  -> KvValue
  -> VaultRequest KvMetadata
patchSecretAt mp path s =
  (setSecret methodPatch mp path . Just $ encodeSecrets s)
  { vaultRequestCT = Just "application/merge-patch+json"
  }

-- | This endpoint provides the ability to patch an existing secret at the
-- specified location. The secret must neither be deleted nor destroyed.
-- A new version will be created by merging provided date with the stored
-- secret.
patchSecret :: KvPath -> KvValue -> VaultRequest KvMetadata
patchSecret = patchSecretAt "secret"

patchSecretCasAt
  :: MountPoint
  -> KvPath
  -> KvVersion
  -> KvValue
  -> VaultRequest KvMetadata
patchSecretCasAt mp path v s =
  (setSecret methodPatch mp path . Just $ encodeSecretsCas v s)
  { vaultRequestCT = Just "application/merge-patch+json"
  }

-- | A CAS version of 'patchSecret' function.
patchSecretCas
  :: KvPath
  -> KvVersion
  -> KvValue
  -> VaultRequest KvMetadata
patchSecretCas = patchSecretCasAt "secret"

data KvSecret = KvSecret
  { data_    :: KvValue
  , metadata :: KvMetadata
  }
  deriving stock (Eq, Ord, Show)

instance FromJSON KvSecret where
  parseJSON = withObject "KvSecret" $ \o ->
    KvSecret <$> o .: "data" <*> o .: "metadata"

readSecretAt :: MountPoint -> KvPath -> VaultRequest KvSecret
readSecretAt mp path =
  mkVaultRequest_ methodGet (secretPath mp path)

-- | This endpoint retrieves the secret at the specified location.
readSecret :: KvPath -> VaultRequest KvSecret
readSecret = readSecretAt "secret"

versionQ :: KvVersion -> [(Text, Maybe Text)]
versionQ v = [("version", Just . Text.pack . show $ unKvVersion v)]

readSecretVersionAt
  :: MountPoint
  -> KvPath
  -> KvVersion
  -> VaultRequest KvSecret
readSecretVersionAt mp path v =
  (mkVaultRequest_ methodGet (secretPath mp path))
  { vaultRequestQuery = versionQ v
  }

-- | This endpoint retrieves a version of the secret at the specified location.
readSecretVersion :: KvPath -> KvVersion -> VaultRequest KvSecret
readSecretVersion = readSecretVersionAt "secret"

deleteSecretAt :: MountPoint -> KvPath -> VaultWrite
deleteSecretAt mp path =
  mkVaultWrite_ methodDelete (secretPath mp path)

-- | This endpoint issues a soft delete of the secret's latest version at the
--specified location.
deleteSecret :: MountPoint -> KvPath -> VaultWrite
deleteSecret = deleteSecretAt

-- | This endpoint issues a soft delete of the specified versions of the secret.
deleteSecretVersions :: KvPath -> [KvVersion] -> VaultWrite
deleteSecretVersions = deleteSecretVersionsAt "secret"

deleteSecretVersionsAt
  :: MountPoint
  -> KvPath
  -> [KvVersion]
  -> VaultWrite
deleteSecretVersionsAt mp path vs =
  mkVaultWrite methodPost
  ("v1":unMountPoint mp:"delete": unKvPath path)
  . Just . encodingToLazyByteString $ pairs ("versions" .= vs)

-- | Undeletes the data for the provided version and path in the key-value store.
undeleteSecretVersions :: KvPath -> [KvVersion] -> VaultWrite
undeleteSecretVersions = undeleteSecretVersionsAt "secret"

undeleteSecretVersionsAt
  :: MountPoint
  -> KvPath
  -> [KvVersion]
  -> VaultWrite
undeleteSecretVersionsAt mp path vs =
  mkVaultWrite methodPost
  ("v1":unMountPoint mp:"undelete": unKvPath path)
  . Just . encodingToLazyByteString $ pairs ("versions" .= vs)

-- | Permanently removes the specified version data for the provided key and version numbers from the key-value store.
destroySecretVersions :: KvPath -> [KvVersion] -> VaultWrite
destroySecretVersions = destroySecretVersionsAt "secret"

destroySecretVersionsAt :: MountPoint -> KvPath -> [KvVersion] -> VaultWrite
destroySecretVersionsAt mp path vs =
  mkVaultWrite methodPost
  ("v1":unMountPoint mp:"destroy": unKvPath path)
  . Just . encodingToLazyByteString $ pairs ("versions" .= vs)

metaPath :: MountPoint -> KvPath -> [Text]
metaPath mp path =
  "v1":unMountPoint mp:"metadata": unKvPath path


listSecretsAt :: MountPoint -> KvPath -> VaultRequest (KeyList KvKey)
listSecretsAt mp path =
  mkVaultRequest_ methodList (metaPath mp path)

-- | This endpoint returns a list of key names at the specified location.
listSecrets :: KvPath -> VaultRequest (KeyList KvKey)
listSecrets = listSecretsAt "secret"


data KvVersionInfo = KvVersionInfo
  { created_time  :: !UTCTime
  , deletion_time :: !(Maybe UTCTime)
  , destroyed     :: !Bool
  } deriving stock (Eq, Show, Generic)

instance FromJSON KvVersionInfo where
  parseJSON = withObject "KvVersionInfo" $ \o -> do
    created_time  <- o .: "created_time"
    deletion_time <- (o .:? "deletion_time") >>= maybe (pure Nothing) mbTime
    destroyed     <- o .: "destroyed"
    pure KvVersionInfo{..}
    where
      mbTime (String t)
        | Text.null t = pure Nothing
      mbTime o = Just <$> parseJSON o


data KvSecretMetadataConfig = KvSecretMetadataConfig
  { max_versions         :: !Int
    -- ^ The number of versions to keep per key. If not set, the backend’s
    -- configured max version is used. Once a key has more than the configured
    -- allowed versions the oldest version will be permanently deleted.
  , cas_required         :: !Bool
    -- ^ If true the key will require the cas parameter to be set on all write
    -- requests. If false, the backend’s configuration will be used.

  , delete_version_after :: !Text -- (string:"0s")
    -- ^ Set the delete_version_after value to a duration to specify the
    -- deletion_time for all new versions written to this key.
    --  Accepts Go duration format string.
  , custom_metadata      :: !(Maybe KvCustomMetadata)
    -- ^ A map of arbitrary string to string valued user-provided metadata meant
    -- to describe the secret.
  } deriving stock (Eq, Show, Generic)

mkKvSecretMetadataConfig :: KvSecretMetadataConfig
mkKvSecretMetadataConfig = KvSecretMetadataConfig
  { max_versions = 0
  , cas_required = False
  , delete_version_after = "0s"
  , custom_metadata = Nothing
  }

-- | This endpoint creates or updates the metadata of a secret at the specified
-- location. It does not create a new version.
putSecretMetadata
  :: KvPath
  -> KvSecretMetadataConfig
  -> VaultWrite
putSecretMetadata = putSecretMetadataAt "secret"

putSecretMetadataAt
  :: MountPoint
  -> KvPath
  -> KvSecretMetadataConfig
  -> VaultWrite
putSecretMetadataAt mp path =
  mkVaultWriteJSON methodGet
  (metaPath mp path)




data KvSecretMetadata = KvSecretMetadata
  { cas_required         :: !Bool
  , created_time         :: !UTCTime
  , current_version      :: !KvVersion
  , delete_version_after :: !Text -- ^ "3h25m19s" bullshit
  , max_versions         :: !Int
  , oldest_version       :: !KvVersion
  , updated_time         :: !UTCTime
  , custom_metadata      :: !(Maybe KvCustomMetadata)
  , versions             :: !(Map.Map KvVersion KvVersionInfo)
  } deriving stock (Eq, Show, Generic)

-- | This endpoint retrieves the metadata and versions for the secret at the
-- specified path. Metadata is version-agnostic.
readSecretMetadata :: KvPath -> VaultRequest KvSecretMetadata
readSecretMetadata = readSecretMetadataAt "secret"

readSecretMetadataAt :: MountPoint -> KvPath -> VaultRequest KvSecretMetadata
readSecretMetadataAt mp path =
  mkVaultRequest_ methodGet
  (metaPath mp path)

-- | This endpoint permanently deletes the key metadata and all version data for the specified key. All version history will be removed.
deleteSecretMetadata :: KvPath -> VaultWrite
deleteSecretMetadata = deleteSecretMetadataAt "secret"

deleteSecretMetadataAt :: MountPoint -> KvPath -> VaultWrite
deleteSecretMetadataAt mp path =
  mkVaultWrite_ methodDelete
  (metaPath mp path)

data KvEngineConfig = KvEngineConfig
  { max_versions         :: Int
    -- ^ The number of versions to keep per key. This value applies to all keys,
    -- but a key's metadata setting can overwrite this value. Once a key has
    -- more than the configured allowed versions the oldest version will be
    -- permanently deleted. When 0 is used or the value is unset, Vault will
    --keep 10 versions.
  , cas_required         :: Bool
    -- ^ If true all keys will require the cas parameter to be set on all write
    -- requests.
  , delete_version_after :: Text
    -- ^ (string:"0s") – If set, specifies the length of time before a version
    -- is deleted. Accepts Go duration format string.
  }
  deriving stock (Eq, Ord, Show, Generic)

-- | This path retrieves the current configuration for the secrets backend at
-- the given path.
readKvEngineConfig :: VaultRequest KvEngineConfig
readKvEngineConfig = readKvEngineConfigAt "secret"

readKvEngineConfigAt :: MountPoint -> VaultRequest KvEngineConfig
readKvEngineConfigAt mp =
  mkVaultRequest_ methodGet
  ["v1", unMountPoint mp, "config"]

-- | This path configures backend level settings that are applied to every key
-- in the key-value store.
putKvEngineConfig :: KvEngineConfig -> VaultWrite
putKvEngineConfig = putKvEngineConfigAt "secret"

putKvEngineConfigAt
  :: MountPoint
  -> KvEngineConfig
  -> VaultWrite
putKvEngineConfigAt mp =
  mkVaultWriteJSON methodPost
  ["v1", unMountPoint mp, "config"]


concat <$> sequence
  [ vaultDeriveFromJSON ''KvSecretMetadata
  , vaultDeriveToJSON ''KvSecretMetadataConfig
  , vaultDeriveToJSON ''KvEngineConfig
  , vaultDeriveFromJSON ''KvEngineConfig
  ]
