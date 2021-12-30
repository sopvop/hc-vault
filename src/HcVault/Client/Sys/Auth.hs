{-# LANGUAGE TemplateHaskell #-}
module HcVault.Client.Sys.Auth
  ( enableAuthMethod
  , disableAuthMethod
  , readAuthMethodTuning
  , tuneAuthMethod
  , AuthMethodEnable(..)
  , AuthMethodConfig(..)
  , AuthMethodTuning(..)
  , mkAuthMethodEnable
  , mkAuthMethodConfig
  , mkAuthMethodTuning
  ) where

import           Data.Aeson (FromJSON (..), withObject, (.!=), (.:?))
import           Data.Text (Text)
import           HcVault.Client.Core


data AuthMethodEnable = AuthMethodEnable
  { type_       :: !Text
    -- ^ Specifies the name of the authentication method type, such as "github"
    -- or "token".
  , description :: !Text
    -- ^ Specifies a human-friendly description of the auth method.
  , local       :: !Bool
    -- ^ Specifies if the auth method is local only. Local auth methods are not
    -- replicated nor (if a secondary) removed by replication.
  , seal_wrap   :: !Bool
    -- ^ Enable seal wrapping for the mount, causing values stored by the mount
    -- to be wrapped by the seal's encryption capability.
  , config      :: !AuthMethodConfig
  } deriving stock (Show, Eq)

mkAuthMethodEnable :: Text -> AuthMethodEnable
mkAuthMethodEnable type_ = AuthMethodEnable
  { type_ = type_
  , description = ""
  , local = False
  , seal_wrap = False
  , config = mkAuthMethodConfig
  }

data AuthMethodConfig = AuthMethodConfig
  { default_lease_ttl            :: !Text
    -- ^ The default lease duration, specified as a string duration like "5s" or "30m".
  , max_lease_ttl                :: !Text
    -- ^ The maximum lease duration, specified as a string duration like "5s" or "30m".
  , audit_non_hmac_request_keys  :: ![Text]
    -- ^ List of keys that will not be HMAC'd by audit devices in the request data object.
  , audit_non_hmac_response_keys :: ![Text]
    -- ^ List of keys that will not be HMAC'd by audit devices in the response data object.
  , listing_visibility           :: !Text
    -- ^ Specifies whether to show this mount in the UI-specific listing endpoint.
  , passthrough_request_headers  :: ![Text]
    -- ^ List of headers to whitelist and pass from the request to the plugin.
  , allowed_response_headers     :: ![Text]
    -- ^ List of headers to whitelist, allowing a plugin to include them in the response. -}
  } deriving stock (Show, Eq)

mkAuthMethodConfig :: AuthMethodConfig
mkAuthMethodConfig = AuthMethodConfig
  { default_lease_ttl = mempty
  , max_lease_ttl = mempty
  , audit_non_hmac_request_keys = mempty
  , audit_non_hmac_response_keys = []
  , listing_visibility = mempty
  , passthrough_request_headers = []
  , allowed_response_headers = []
  }

-- | This endpoint enables a new auth method. After enabling, the auth method
-- can be accessed and configured via the auth path specified as part of the
-- URL. This auth path will be nested under the auth prefix.
enableAuthMethod :: MountPoint -> AuthMethodEnable -> VaultWrite
enableAuthMethod path conf =
  mkVaultWriteJSON methodPost
  (pathV1 ["v1", "sys", "auth", unMountPoint path])
  conf

-- | This endpoint disables the auth method at the given auth path.
disableAuthMethod :: MountPoint -> VaultWrite
disableAuthMethod path =
  mkVaultWrite methodDelete
  (pathV1 ["sys", "auth", unMountPoint path])
  Nothing

data AuthMethodTuning = AuthMethodTuning
  { default_lease_ttl            :: Int
    -- ^ Specifies the default time-to-live. If set on a specific auth path,
    -- this overrides the global default.
  , max_lease_ttl                :: Int
    -- ^ Specifies the maximum time-to-live. If set on a specific auth path,
    -- this overrides the global default.
  , description                  :: Text
    -- ^ Specifies the description of the mount. This overrides the current
    -- stored value, if any.
  , audit_non_hmac_request_keys  :: [Text]
    -- ^ Specifies the list of keys that will not be HMAC'd by audit devices
    -- in the request data object.
  , audit_non_hmac_response_keys :: [Text]
    -- ^ Specifies the list of keys that will not be HMAC'd by audit devices in
    -- the response data object.
  , listing_visibility           :: Text
    -- ^ Specifies whether to show this mount in the UI-specific listing
    -- endpoint. Valid values are "unauth" or "".
  , passthrough_request_headers  :: [Text]
    -- ^ List of headers to whitelist and pass from the request to the plugin.
  , allowed_response_headers     :: [Text]
    -- ^ List of headers to whitelist, allowing a plugin to include them in the
    -- response.
  , token_type                   :: Text
    -- ^ Specifies the type of tokens that should be returned by the mount.
    -- The following values are available:
    --  default-service: Unless the auth method requests a different type, issue service tokens
    --  default-batch: Unless the auth method requests a different type, issue batch tokens
    --  service: Override any auth method preference and always issue service tokens from this mount
    --  batch: Override any auth method preference and always issue batch tokens from this mount
  } deriving stock (Eq, Show)

mkAuthMethodTuning :: AuthMethodTuning
mkAuthMethodTuning = AuthMethodTuning
  { default_lease_ttl = 0
  , max_lease_ttl = 0
  , description = mempty
  , audit_non_hmac_request_keys = []
  , audit_non_hmac_response_keys = []
  , listing_visibility = mempty
  , passthrough_request_headers = []
  , allowed_response_headers = []
  , token_type = mempty
  }

instance FromJSON AuthMethodTuning where
  parseJSON = withObject "AuthMethodTuning" $ \o -> do
    default_lease_ttl <- o .:? "default_lease_ttl" .!= 0
    max_lease_ttl <- o .:? "max_lease_ttl" .!= 0
    description <- o .:? "description" .!= mempty
    audit_non_hmac_request_keys <- o .:? "audit_non_hmac_request_keys" .!= []
    audit_non_hmac_response_keys <- o .:? "audit_non_hmac_response_keys" .!= []
    listing_visibility <- o .:? "listing_visibility" .!= mempty
    passthrough_request_headers <- o .:? "passthrough_request_headers" .!= []
    allowed_response_headers <- o .:? "allowed_response_headers" .!= []
    token_type <- o .:? "token_type" .!= mempty
    pure AuthMethodTuning{..}


-- | This endpoint reads the given auth path's configuration.
readAuthMethodTuning :: MountPoint -> VaultQuery AuthMethodTuning
readAuthMethodTuning mp =
  mkVaultQueryJSON_ methodGet
  (pathV1 ["v1", "sys", "auth", unMountPoint mp, "tune"])

-- | Tune configuration parameters for a given auth path.
tuneAuthMethod :: MountPoint -> AuthMethodTuning -> VaultWrite
tuneAuthMethod mp conf =
  mkVaultWriteJSON methodPost
  (pathV1 ["sys", "auth", unMountPoint mp, "tune"])
  conf

concat <$> sequence
  [ vaultDeriveToJSON ''AuthMethodConfig
  , vaultDeriveToJSON ''AuthMethodEnable
  , vaultDeriveToJSON ''AuthMethodTuning
  ]

{-
xx :: VaultClient -> IO ()
xx c = vaultWrite c $ enableAuth "xxx" $ AuthEnable "" "approle" (AuthConfig "" "")

foo = do
  m <- newManager defaultManagerSettings
  c <- mkVaultClient m "http://localhost:8200" (Just "s.lNZy9UolVZ7B4sSI7w5F8YeT")
  vaultWrite c $ disableAuth "xxx"
  xx c


-}
