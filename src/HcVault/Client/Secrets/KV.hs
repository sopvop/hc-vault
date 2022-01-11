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
  , destroySecretAt
  , destroySecret
  , KvPath
  , KvValue
  , KvSecret
  , KvMetadata(..)
  ) where

import           Data.Aeson
    (FromJSON (..), ToJSON, Value (..), pairs, withObject, (.:), (.:?), (.=))
import           Data.Aeson.Encoding (encodingToLazyByteString, pair)
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as LBS
import           Data.List.NonEmpty (NonEmpty (..))
import qualified Data.List.NonEmpty as NonEmpty
import qualified Data.Map.Strict as Map
import           Data.Text (Text)
import qualified Data.Text as Text
import           Data.Time (UTCTime)
import           HcVault.Client.Core

data KvKeys
  = KvDir Text
  | KvKey Text
  deriving stock (Show, Eq, Ord)

newtype KvPath = KvPath
  { unKvPath :: NonEmpty Text }
  deriving stock (Show, Eq, Ord)

newtype KvVersion = KvVersion
  { unKvVersion :: Int }
  deriving stock (Show, Eq, Ord)
  deriving newtype (FromJSON, ToJSON)

type KvValue = Map.Map Text Value

data KvMetadata = KvMetadata
  { created_time    :: !UTCTime
  , deletion_time   :: !(Maybe UTCTime)
  , destroyed       :: !Bool
  , version         :: !KvVersion
  , custom_metadata :: !(Maybe (Map.Map Text Text))
  } deriving stock (Eq, Ord, Show)

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
  "v1":unMountPoint mp:"data": NonEmpty.toList (unKvPath path)

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
deleteSecretVersions = deleteSecretVersionsAt "secret"

deleteSecretVersionsAt
  :: MountPoint
  -> KvPath
  -> [KvVersion]
  -> VaultWrite
deleteSecretVersionsAt mp path vs =
  mkVaultWrite methodPost
  ("v1":unMountPoint mp:"delete": NonEmpty.toList (unKvPath path))
  . Just . encodingToLazyByteString $ pairs ("versions" .= vs)

-- | Undeletes the data for the provided version and path in the key-value store.
undeleteSecretVersions = undeleteSecretVersionsAt "secret"

undeleteSecretVersionsAt
  :: MountPoint
  -> KvPath
  -> [KvVersion]
  -> VaultWrite
undeleteSecretVersionsAt mp path vs =
  mkVaultWrite methodPost
  ("v1":unMountPoint mp:"undelete": NonEmpty.toList (unKvPath path))
  . Just . encodingToLazyByteString $ pairs ("versions" .= vs)

-- | Permanently removes the specified version data for the provided key and version numbers from the key-value store.
destroySecretVersions :: KvPath -> [KvVersion] -> VaultWrite
destroySecretVersions = destroySecretVersionsAt "secret"

destroySecretVersionsAt :: MountPoint -> KvPath -> [KvVersion] -> VaultWrite
destroySecretVersionsAt mp path vs =
  mkVaultWrite methodPost
  ("v1":unMountPoint mp:"destroy": NonEmpty.toList (unKvPath path))
  . Just . encodingToLazyByteString $ pairs ("versions" .= vs)

-- | This endpoint permanently deletes the key metadata and all version data for the specified key. All version history will be removed.
destroySecret :: KvPath -> VaultWrite
destroySecret = destroySecretAt "secret"

destroySecretAt :: MountPoint -> KvPath -> VaultWrite
destroySecretAt mp path =
  mkVaultWrite_ methodDelete
  ("v1":unMountPoint mp:"metadata": NonEmpty.toList (unKvPath path))

