{-# LANGUAGE TemplateHaskell #-}
module HcVault.Client.Auth.AppRole
  ( appRoleListRoles
  , appRoleListRolesAt
  , appRoleCreateRoleAt
  , appRoleCreateRole
  , appRoleReadRole
  , appRoleReadRoleAt
  , appRoleDeleteRole
  , appRoleDeleteRoleAt
  , appRoleReadRoleId
  , appRoleReadRoleIdAt
  , appRoleUpdateRoleId
  , appRoleUpdateRoleIdAt
  , appRoleGenerateSecretId
  , appRoleGenerateSecretIdAt
  , appRoleListSecretIdAccessors
  , appRoleListSecretIdAccessorsAt
  , readAppRoleSecretIdInfo
  , readAppRoleSecretIdInfoAt
  , readAppRoleSecretIdAccessorInfo
  , readAppRoleSecretIdAccessorInfoAt
  , destroyAppRoleSecretIdAccessor
  , destroyAppRoleSecretIdAccessorAt
  , appRoleLogin
  , appRoleLoginAt
  , appRoleTidyTokens
  , appRoleTidyTokensAt
  , AppRole(..)
  , mkAppRole
  , AppRoleName(..)
  , AppRoleId(..)
  , AppRoleSecretId(..)
  , AppRoleRoleId(..)
  , AppRoleGenerateSecretId(..)
  , mkAppRoleGenerateSecretId
  , AppRoleGeneratedSecretId(..)
  ) where

import           Data.Aeson
    (FromJSON (..), KeyValue, ToJSON (..), encode, fromEncoding, object, pairs,
    withObject, (.!=), (.:), (.:?), (.=))
import qualified Data.ByteString.Builder as BL
import qualified Data.ByteString.Lazy as LBS
import           Data.Map (Map)
import           Data.String (IsString)
import           Data.Text (Text)
import qualified Data.Text.Encoding as Text
import           Data.Time (UTCTime)
import           HcVault.Client.Core

newtype AppRoleName = AppRoleName { unRoleName :: Text }
  deriving stock (Show, Eq, Ord)
  deriving newtype (FromJSON, ToJSON, IsString)

data AppRole = AppRole
   { bind_secret_id          :: !Bool
     -- ^ Require secret_id to be presented when logging in using this AppRole.
   , secret_id_bound_cidrs   :: ![Text]
     -- ^ Comma-separated string or list of CIDR blocks; if set, specifies
     -- blocks of IP addresses which can perform the login operation.
   , secret_id_num_uses      :: !Int
     -- ^ Number of times any particular SecretID can be used to fetch a token
     -- from this AppRole, after which the SecretID will expire.
     -- A value of zero will allow unlimited uses.
   , secret_id_ttl           :: !Int
     -- ^ Duration in either an integer number of seconds (3600) or an integer
     -- time unit (60m) after which any SecretID expires.
   , local_secret_ids        :: !Bool
     -- ^ If set, the secret IDs generated using this role will be cluster local.
     -- This can only be set during role creation and once set, it can't be reset later.
   , token_ttl               :: !Int
     -- ^ The incremental lifetime for generated tokens. This current value of
     -- this will be referenced at renewal time.
   , token_max_ttl           :: !Int
     -- ^ The maximum lifetime for generated tokens. This current value of this
     -- will be referenced at renewal time.
   , token_policies          :: ![PolicyName]
     -- ^ List of policies to encode onto generated tokens. Depending on the
     -- auth method, this list may be supplemented by user/group/other values.

   , token_bound_cidrs       :: ![Text]
     -- ^ List of CIDR blocks; if set, specifies blocks of IP addresses which
     -- can authenticate successfully, and ties the resulting token to these
     -- blocks as well.
   , token_explicit_max_ttl  :: !Int
     -- ^ If set, will encode an explicit max TTL onto the token. This is a hard
     -- cap even if token_ttl and token_max_ttl would otherwise allow a renewal.
   , token_no_default_policy :: !Bool
     -- ^ If set, the default policy will not be set on generated tokens;
     -- otherwise it will be added to the policies set in token_policies.
   , token_num_uses          :: !Int
     -- ^ The maximum number of times a generated token may be used (within its
     -- lifetime); 0 means unlimited. If you require the token to have the
     -- ability to create child tokens, you will need to set this value to 0.
   , token_period            :: !Int
     -- ^ The period, if any, to set on the token.
   , token_type              :: !Text
     -- ^ The type of token that should be generated. Can be service, batch, or
     -- default to use the mount's tuned default (which unless changed will be
     -- service tokens). For token store roles, there are two additional
     -- possibilities: default-service and default-batch which specify the type
     -- to return unless the client requests a different type at generation time.
   }
  deriving stock (Eq, Ord, Show)

instance FromJSON AppRole where
  parseJSON = withObject "AppRole" $ \o -> do
     bind_secret_id          <- o .: "bind_secret_id"
     secret_id_bound_cidrs   <- o .:? "secret_id_bound_cirds" .!= []
     secret_id_num_uses      <- o .: "secret_id_num_uses"
     secret_id_ttl           <- o .: "secret_id_ttl"
     local_secret_ids        <- o .: "local_secret_ids"
     token_ttl               <- o .: "token_ttl"
     token_max_ttl           <- o .: "token_max_ttl"
     token_policies          <- o .: "token_policies"
     token_bound_cidrs       <- o .: "token_bound_cidrs"
     token_explicit_max_ttl  <- o .: "token_explicit_max_ttl"
     token_no_default_policy <- o .: "token_no_default_policy"
     token_num_uses          <- o .: "token_num_uses"
     token_period            <- o .: "token_period"
     token_type              <- o .: "token_type"
     pure AppRole{..}

mkAppRole :: AppRole
mkAppRole = AppRole
  { bind_secret_id = True
  , secret_id_bound_cidrs = []
  , secret_id_num_uses = 0
  , secret_id_ttl = 0
  , local_secret_ids = False
  , token_ttl = 0
  , token_max_ttl = 0
  , token_policies = []
  , token_bound_cidrs = []
  , token_explicit_max_ttl = 0
  , token_no_default_policy = False
  , token_num_uses = 0
  , token_period = 0
  , token_type = ""
  }

appRoleListRolesAt
  :: MountPoint
  -> VaultRequest (VaultResponse (KeyList AppRoleName))
appRoleListRolesAt mp = mkVaultRequest methodList
  ["v1", "auth", unMountPoint mp, "role"]
   Nothing Expects

appRoleListRoles :: VaultRequest (VaultResponse (KeyList AppRoleName))
appRoleListRoles = appRoleListRolesAt "approle"

appRoleReadRoleAt
  :: MountPoint
  -> AppRoleName
  -> VaultRequest AppRole
appRoleReadRoleAt mp nm = mkVaultRequest methodGet
  ["v1", "auth", unMountPoint mp, "role", unRoleName nm]
  Nothing Expects

appRoleReadRole :: AppRoleName -> VaultRequest AppRole
appRoleReadRole = appRoleReadRoleAt "approle"

appRoleCreateRoleAt
  :: MountPoint
  -> AppRoleName
  -> AppRole
  -> VaultRequest ()
appRoleCreateRoleAt mp nm v = mkVaultRequestJSON methodPost
  ["v1", "auth", unMountPoint mp, "role", unRoleName nm]
  v ExpectsNoContent

appRoleCreateRole :: AppRoleName -> AppRole -> VaultRequest ()
appRoleCreateRole = appRoleCreateRoleAt "approle"

appRoleDeleteRoleAt
  :: MountPoint
  -> AppRoleName
  -> VaultRequest ()
appRoleDeleteRoleAt mp nm = mkVaultRequest methodDelete
  ["v1", "auth", unMountPoint mp, "role", unRoleName nm]
  Nothing ExpectsNoContent

appRoleDeleteRole :: AppRoleName -> VaultRequest ()
appRoleDeleteRole = appRoleDeleteRoleAt "approle"

newtype AppRoleId = AppRoleId
  { unAppRoleId :: Text }
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON)

newtype AppRoleSecretId = AppRoleSecretId
  { unAppRoleSecretId :: Text }
  deriving stock (Eq, Ord)
  deriving newtype (FromJSON, ToJSON)

instance Show AppRoleSecretId where
  show _ = "AppRoleSecretId { unAppRoleSecretId = \"***SECRET***\" }"

newtype AppRoleRoleId = AppRoleRoleId
  { role_id :: AppRoleId }


instance FromJSON AppRoleRoleId where
  parseJSON = withObject "AppRoleRoleId" $ \o ->
    AppRoleRoleId <$> o .: "role_id"

instance ToJSON AppRoleRoleId where
  toJSON AppRoleRoleId{..} =
    object ["role_id" .= role_id]
  toEncoding AppRoleRoleId{..} =
    pairs $ "role_id" .= role_id


appRoleReadRoleIdAt
  :: MountPoint
  -> AppRoleName
  -> VaultRequest  (VaultResponse AppRoleRoleId)
appRoleReadRoleIdAt mp nm = mkVaultRequest methodGet
  ["v1", "auth", unMountPoint mp, "role", unRoleName nm, "role-id"]
  Nothing Expects

appRoleReadRoleId
  :: AppRoleName
  -> VaultRequest (VaultResponse AppRoleRoleId)
appRoleReadRoleId = appRoleReadRoleIdAt "approle"

appRoleUpdateRoleIdAt
  :: MountPoint
  -> AppRoleName
  -> AppRoleId
  -> VaultRequest ()
appRoleUpdateRoleIdAt mp nm v = mkVaultRequestJSON methodPost
  ["v1", "auth", unMountPoint mp, "role", unRoleName nm, "role-id"]
  (AppRoleRoleId v) ExpectsNoContent

appRoleUpdateRoleId :: AppRoleName -> AppRoleId -> VaultRequest ()
appRoleUpdateRoleId = appRoleUpdateRoleIdAt "approle"


data AppRoleGenerateSecretId = AppRoleGenerateSecretId
  { metadata          :: Map Text Text
    -- ^ Metadata to be tied to the SecretID. This should be a JSON-formatted
    -- string containing the metadata in key-value pairs. This metadata will be
    -- set on tokens issued with this SecretID, and is logged in audit logs in
    -- plaintext.
  , cidr_list         :: [Text]
    -- ^ Comma separated string or list of CIDR blocks enforcing secret IDs to
    -- be used from specific set of IP addresses. If bound_cidr_list is set on
    -- the role, then the list of CIDR blocks listed here should be a subset of
    -- the CIDR blocks listed on the role.
  , token_bound_cidrs :: [Text]
    -- ^ Comma-separated string or list of CIDR blocks; if set, specifies blocks
    -- of IP addresses which can use the auth tokens generated by this SecretID.
    -- Overrides any role-set value but must be a subset.
  }
  deriving stock (Eq, Show)

mkAppRoleGenerateSecretId :: AppRoleGenerateSecretId
mkAppRoleGenerateSecretId = AppRoleGenerateSecretId
  { metadata = mempty
  , cidr_list = []
  , token_bound_cidrs = []
  }

generatePairs :: KeyValue a => AppRoleGenerateSecretId -> [a]
generatePairs AppRoleGenerateSecretId{..} =
  [ "metadata" .= (Text.decodeUtf8 . LBS.toStrict $ encode metadata)
  , "cidr_list" .= cidr_list
  , "token_bound_cidrs" .= token_bound_cidrs
  ]
{-# INLINE generatePairs #-}

instance ToJSON AppRoleGenerateSecretId where
  toJSON = object . generatePairs
  toEncoding = pairs . mconcat . generatePairs

newtype AppRoleSecretIdAccessor = AppRoleSecretIdAccessor
  { unAppRoleSecretIdAccessor :: Text }
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON)

data AppRoleGeneratedSecretId = AppRoleGeneratedSecretId
  { secret_id          :: AppRoleSecretId
  , secret_id_accessor :: AppRoleSecretIdAccessor
  , secret_id_ttl      :: Int
  }
  deriving stock (Eq, Show)

appRoleGenerateSecretIdAt
  :: MountPoint
  -> AppRoleName
  -> AppRoleGenerateSecretId
  -> VaultRequest (VaultResponse AppRoleGeneratedSecretId)
appRoleGenerateSecretIdAt mp nm v =
  mkVaultRequestJSON methodPost
  ["v1", "auth", unMountPoint mp, "role", unRoleName nm, "secret-id"]
  v Expects

appRoleGenerateSecretId
  :: AppRoleName
  -> AppRoleGenerateSecretId
  -> VaultRequest (VaultResponse AppRoleGeneratedSecretId)
appRoleGenerateSecretId  = appRoleGenerateSecretIdAt "approle"

appRoleListSecretIdAccessorsAt
  :: MountPoint
  -> AppRoleName
  -> VaultRequest (VaultResponse (KeyList AppRoleSecretIdAccessor))
appRoleListSecretIdAccessorsAt mp nm =
  mkVaultRequest methodList
  ["v1", "auth", unMountPoint mp, "role", unRoleName nm, "secret-id"]
  Nothing Expects

appRoleListSecretIdAccessors
  :: AppRoleName
  -> VaultRequest (VaultResponse (KeyList AppRoleSecretIdAccessor))
appRoleListSecretIdAccessors = appRoleListSecretIdAccessorsAt "approle"


data AppRoleSecretIdInfo = AppRoleSecretIdInfo
  { cidr_list          :: [Text]
  , creation_time      :: UTCTime
  , expiration_time    :: UTCTime
  , last_updated_time  :: UTCTime
  , metadata           :: Map Text Text
  , secret_id_accessor :: AppRoleSecretIdAccessor
  , secret_id_num_uses :: Int
  , secret_id_ttl      :: Int
  , token_bound_cidrs  :: [Text]
  }
  deriving stock (Eq, Show)



readAppRoleSecretIdInfoAt
  :: MountPoint
  -> AppRoleName
  -> AppRoleSecretId
  -> VaultRequest (VaultResponse AppRoleSecretIdInfo)
readAppRoleSecretIdInfoAt mp nm sec =
  mkVaultRequest methodPost
  ["v1", "auth", unMountPoint mp, "role", unRoleName nm, "secret-id", "lookup"]
  (Just payload) Expects
  where
    payload = BL.toLazyByteString . fromEncoding . pairs $ "secret_id" .= sec

readAppRoleSecretIdInfo
  :: AppRoleName
  -> AppRoleSecretId
  -> VaultRequest (VaultResponse AppRoleSecretIdInfo)
readAppRoleSecretIdInfo = readAppRoleSecretIdInfoAt "approle"


readAppRoleSecretIdAccessorInfoAt
  :: MountPoint
  -> AppRoleName
  -> AppRoleSecretIdAccessor
  -> VaultRequest (VaultResponse AppRoleSecretIdInfo)
readAppRoleSecretIdAccessorInfoAt mp nm sec =
  mkVaultRequest methodPost
  ["v1", "auth", unMountPoint mp, "role", unRoleName nm, "secret-id-accessor", "lookup"]
  (Just payload) Expects
  where
    payload = BL.toLazyByteString . fromEncoding . pairs $ "secret_id_accessor" .= sec

readAppRoleSecretIdAccessorInfo
  :: AppRoleName
  -> AppRoleSecretIdAccessor
  -> VaultRequest (VaultResponse AppRoleSecretIdInfo)
readAppRoleSecretIdAccessorInfo = readAppRoleSecretIdAccessorInfoAt "approle"

destroyAppRoleSecretIdAccessorAt
  :: MountPoint
  -> AppRoleName
  -> AppRoleSecretIdAccessor
  -> VaultRequest ()
destroyAppRoleSecretIdAccessorAt mp nm sec =
  mkVaultRequest methodPost
  ["v1", "auth", unMountPoint mp, "role", unRoleName nm, "secret-id-accessor", "destroy"]
  (Just payload) Expects
  where
    payload = BL.toLazyByteString . fromEncoding . pairs $ "secret_id_accessor" .= sec

destroyAppRoleSecretIdAccessor
  :: AppRoleName
  -> AppRoleSecretIdAccessor
  -> VaultRequest ()
destroyAppRoleSecretIdAccessor = destroyAppRoleSecretIdAccessorAt "approle"

appRoleLoginAt
  :: MountPoint
  -> AppRoleId
  -> AppRoleSecretId
  -> VaultRequest AuthResponse
appRoleLoginAt mp rid sid =
  mkVaultRequest methodPost
  ["v1", "auth", unMountPoint mp, "login"]
  (Just payload) Expects
  where
    payload = BL.toLazyByteString . fromEncoding . pairs
      $ "role_id" .= rid <> "secret_id" .= sid

appRoleLogin
  :: AppRoleId
  -> AppRoleSecretId
  -> VaultRequest AuthResponse
appRoleLogin = appRoleLoginAt "approle"

appRoleTidyTokensAt :: MountPoint -> VaultRequest (VaultResponse NoData)
appRoleTidyTokensAt mp =
  mkVaultRequest methodPost
  ["v1", "auth", unMountPoint mp, "tidy", "secret-id"]
  Nothing Expects

appRoleTidyTokens :: VaultRequest (VaultResponse NoData)
appRoleTidyTokens = appRoleTidyTokensAt "approle"

concat <$> sequence
  [ vaultDeriveToJSON ''AppRole
  , vaultDeriveFromJSON ''AppRoleGeneratedSecretId
  , vaultDeriveFromJSON ''AppRoleSecretIdInfo
  , vaultDeriveToJSON ''AppRoleSecretIdInfo
  ]
