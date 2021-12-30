{-# LANGUAGE TemplateHaskell #-}
module HcVault.Client.Sys.Secrets
  ( secretsEngineCreate
  , secretsEngineDisable
  , SecretsEngineCreate(..)
  , mkSecretsEngineCreate
  , SecretsEngineConfig(..)
  , mkSecretsEngineConfig
  , secretsEngineGetInfo
  , secretsEngineListMounts
  , secretsEngineReadMount
  , secretsEngineTuneMount
  ) where

import           Data.Aeson (FromJSON (..), ToJSON, withObject, (.!=), (.:?))
import           Data.Map.Strict (Map)
import           Data.Text (Text)
import           Data.UUID.Types (UUID)

import           HcVault.Client.Core


data SecretsEngineConfig = SecretsEngineConfig
  { default_lease_ttl            :: !Int
    -- ^ The default lease duration, specified as a string duration like "5s" or "30m".
  , max_lease_ttl                :: !Int
    -- ^ The maximum lease duration, specified as a string duration like "5s" or "30m".
  , force_no_cache               :: !Bool
    -- ^ Disable caching.
  , audit_non_hmac_request_keys  :: ![Text]
    -- ^ List of keys that will not be HMAC'd by audit devices in the request
    -- data object.
  , audit_non_hmac_response_keys :: ![Text]
    -- ^ List of keys that will not be HMAC'd by audit devices in the response
    -- data object.
  , listing_visibility           :: !Text
    -- ^ Specifies whether to show this mount in the UI-specific listing
    -- endpoint. Valid values are "unauth" or "hidden". If not set, behaves like
    -- "hidden".
  , passthrough_request_headers  :: ![Text]
    -- ^ List of headers to whitelist and pass from the request to the plugin.
  , allowed_response_headers     :: ![Text]
    -- ^ List of headers to whitelist, allowing a plugin to include them in the response.
  }
  deriving stock (Show, Eq)

mkSecretsEngineConfig :: SecretsEngineConfig
mkSecretsEngineConfig = SecretsEngineConfig
  { default_lease_ttl = 0
  , max_lease_ttl = 0
  , force_no_cache = False
  , audit_non_hmac_request_keys = []
  , audit_non_hmac_response_keys = []
  , listing_visibility = ""
  , passthrough_request_headers = []
  , allowed_response_headers = []
  }

instance FromJSON SecretsEngineConfig where
  parseJSON = withObject "SecretsEngineConfig" $ \o -> do
    default_lease_ttl            <- o .:? "default_lease_ttl" .!= 0
    max_lease_ttl                <- o .:? "max_lease_ttl" .!= 0
    force_no_cache               <- o .:? "force_no_cache" .!= False
    audit_non_hmac_request_keys  <- o .:? "audit_non_hmac_request_keys" .!= []
    audit_non_hmac_response_keys <- o .:? "audit_non_hmac_response_keys" .!= []
    listing_visibility           <- o .:? "listing_visibility" .!= ""
    passthrough_request_headers  <- o .:? "passthrough_request_headers" .!= []
    allowed_response_headers     <- o .:? "allowed_response_headers" .!= []
    pure SecretsEngineConfig{..}

data SecretsEngineCreate = SecretsEngineCreate
  { type_                   :: Text
    -- ^ Specifies the type of the backend, such as "aws".
  , description             :: Text
    -- ^ Specifies the human-friendly description of the mount.
  , config                  :: SecretsEngineConfig
  , options                 :: !(Maybe (Map Text Text))
  -- ^ Specifies mount type specific options that are passed to the backend.
  , version                 :: Text
    -- ^ The version of the KV to mount. Set to "2" for mount KV v2.
  , local                   :: Bool
    -- ^ Specifies if the secrets engine is a local mount only. Local mounts are
    -- not replicated nor (if a secondary) removed by replication.
  , seal_wrap               :: Bool
    -- ^ Enable seal wrapping for the mount, causing values stored by the mount
    -- to be wrapped by the seal's encryption capability.
  , external_entropy_access :: Bool
    -- ^ Enable the secrets engine to access Vault's external entropy
  }
  deriving stock (Show, Eq)

mkSecretsEngineCreate :: Text -> SecretsEngineCreate
mkSecretsEngineCreate type_ = SecretsEngineCreate
  { type_ = type_
  , description = ""
  , config = mkSecretsEngineConfig
  , options = Nothing
  , version = "1"
  , local = False
  , seal_wrap = False
  , external_entropy_access = False
  }

secretsEngineCreate
  :: MountPoint
  -> SecretsEngineCreate
  -> VaultWrite
secretsEngineCreate mp v =
  mkVaultWriteJSON methodPost ["v1", "sys", "mounts", unMountPoint mp] v

secretsEngineDisable :: MountPoint -> VaultWrite
secretsEngineDisable mp =
  mkVaultWrite_ methodDelete ["v1", "sys", "mounts", unMountPoint mp]

newtype SecretsEngineAccessor = SecretsEngineAccessor
  { unSecretsEngineAcceessor :: Text }
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON)

data SecretsEngineInfo = SecretsEngineInfo
  { type_                   :: Text
  , description             :: Text
  , config                  :: SecretsEngineConfig
  , options                 :: !(Maybe (Map Text Text))
  , local                   :: Bool
  , seal_wrap               :: Bool
  , external_entropy_access :: Bool
  , accessor                :: SecretsEngineAccessor
  , uuid                    :: UUID
  }
  deriving stock (Show, Eq)

secretsEngineGetInfo
  :: MountPoint
  -> VaultRequest SecretsEngineInfo
secretsEngineGetInfo mp =
  mkVaultRequest_ methodGet ["v1", "sys", "mounts", unMountPoint mp]

secretsEngineListMounts :: VaultRequest (Map MountPoint SecretsEngineInfo)
secretsEngineListMounts =
  mkVaultRequest_ methodGet ["v1", "sys", "mounts"]

secretsEngineReadMount
  :: MountPoint
  -> VaultRequest SecretsEngineConfig
secretsEngineReadMount mp =
  mkVaultRequest_ methodGet ["v1", "sys", "mounts", unMountPoint mp, "tune"]

secretsEngineTuneMount
  :: MountPoint
  -> SecretsEngineConfig
  -> VaultWrite
secretsEngineTuneMount mp conf =
  mkVaultWriteJSON methodPost ["v1", "sys", "mounts", unMountPoint mp, "tune"]
  conf

concat <$> sequence
  [ vaultDeriveToJSON ''SecretsEngineConfig
  , vaultDeriveToJSON ''SecretsEngineCreate
  , vaultDeriveFromJSON ''SecretsEngineInfo
  ]
