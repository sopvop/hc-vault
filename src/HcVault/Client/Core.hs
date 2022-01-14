{-# LANGUAGE DeriveFoldable    #-}
{-# LANGUAGE DeriveFunctor     #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs             #-}
module  HcVault.Client.Core
  ( VaultToken(..)
  , VaultRequest (..)
  , VaultWrite (..)
  , WrappingToken(..)
  , mkVaultRequest
  , mkVaultRequest_
  , mkVaultRequestJSON
  , mkVaultWrite
  , mkVaultWrite_
  , mkVaultWriteJSON
  , VaultResponse(..)
  , Auth(..)
  , MountPoint(..)
  , WrapInfo(..)
  , LeaseId(..)
  , RequestId(..)
  , KeyList(..)
  , PolicyName(..)
  , VaultClientError(..)
  , methodGet
  , methodPost
  , methodPut
  , methodDelete
  , methodList
  , methodPatch
  , vaultDeriveToJSON
  , vaultDeriveFromJSON
  ) where

import           Control.Exception (Exception)
import           Data.Aeson
    (FromJSON (..), FromJSONKey (..), FromJSONKeyFunction (..), ToJSON (..),
    encode, withObject, (.!=), (.:), (.:?))
import           Data.Aeson.TH
    (Options (..), defaultOptions, deriveFromJSON, deriveToJSON)
import           Data.ByteString
import qualified Data.ByteString.Lazy as LBS
import           Data.Coerce (coerce)
import           Data.Map.Strict (Map)
import           Data.String (IsString)
import           Data.Text (Text)
import qualified Data.Text as Text
import           Data.Time (UTCTime)
import           Language.Haskell.TH.Syntax (Dec, Name, Q)
import           Network.HTTP.Types.Method
import           Network.HTTP.Types.Status
import           Network.HTTP.Types.URI

newtype MountPoint = MountPoint
  { unMountPoint :: Text }
  deriving stock (Eq, Ord, Show)
  deriving newtype (IsString)

instance FromJSONKey MountPoint where
  fromJSONKey = FromJSONKeyText $
    MountPoint . Text.dropWhileEnd (== '/')
  fromJSONKeyList = FromJSONKeyText $
    fmap (MountPoint . Text.dropWhileEnd (== '/')) . Text.splitOn ","

newtype VaultToken = VaultToken { unVaultToken :: Text }
  deriving stock (Eq, Ord)
  deriving newtype (IsString, FromJSON, ToJSON)

instance Show VaultToken where
  show _ = "VaultToken { unVaultToken = \"***SECRET***\" }"

newtype WrappingToken a = WrappingToken
  { getWrappingToken :: VaultToken
  }
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON)

data NoData = NoData
  deriving stock (Eq, Ord, Show)

instance FromJSON NoData where
  parseJSON _ = pure NoData

data VaultRequest a = VaultRequest
  { vaultRequestMethod  :: !Method
  , vaultRequestPath    :: ![Text]
  , vaultRequestQuery   :: !QueryText
  , vaultRequestData    :: !(Maybe LBS.ByteString)
  , vaultRequestWrapTTL :: !(Maybe Int)
  , vaultRequestCT      :: !(Maybe ByteString)
  };

data VaultWrite = VaultWrite
  { vaultWriteMethod :: !Method
  , vaultWritePath   :: ![Text]
  , vaultWriteData   :: !(Maybe LBS.ByteString)
  };

newtype LeaseId = LeaseId { unLeaseId :: Text }
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON)

newtype RequestId = RequestId { unRequestId :: Text }
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON)

newtype AuthAccessor = AuthAccessor { unAuthAccessor :: Text }
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON)

newtype PolicyName = PolicyName { unPolicyName :: Text }
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON, IsString)

newtype KeyList a = KeyList { getKeyList::[a] }
  deriving stock (Eq, Show)

instance FromJSON a => FromJSON (KeyList a) where
  parseJSON = withObject "KeyList" $ \o ->
    coerce @(_ [a]) @(_ (KeyList a)) (o .: "keys")


data Auth = Auth
  { renewable      :: !Bool
  , lease_duration :: !Int
  , metadata       :: !(Map Text Text)
  , token_policies :: ![PolicyName]
  , accessor       :: !AuthAccessor
  , client_token   :: !VaultToken
  }
  deriving stock (Eq, Show)

instance FromJSON Auth where
  parseJSON = withObject "Auth" $ \o -> do
    renewable      <- o .: "renewable"
    lease_duration <- o .: "lease_duration"
    token_policies <- o .: "token_policies"
    accessor       <- o .: "accessor"
    client_token   <- o .: "client_token"
    metadata       <- o .:? "metadata" .!= mempty
    pure Auth{..}

data WrapInfo a = WrapInfo
  { token         :: WrappingToken a
  , ttl           :: Int
  , creation_time :: UTCTime
  , creation_path :: Text
  }
  deriving stock (Eq, Show)

instance FromJSON (WrapInfo a) where
  parseJSON = withObject "WrapInfo" $ \o -> do
    token         <- o .: "token"
    ttl           <- o .: "ttl"
    creation_time <- o .: "creation_time"
    creation_path <- o .: "creation_path"
    pure WrapInfo{..}

data VaultResponse a = VaultResponse
  { lease_id       :: !LeaseId
  , renewable      :: !Bool
  , request_id     :: !RequestId
  , lease_duration :: !Int
  , warnings       :: ![Text]
  , data_          :: !a
  }
  deriving stock (Show, Eq, Functor, Foldable, Traversable)

instance {-# OVERLAPPABLE #-} FromJSON a => FromJSON (VaultResponse a) where
  parseJSON = withObject "VaultResponse" $ \o -> do
    lease_id        <- o .: "lease_id"
    renewable       <- o .: "renewable"
    request_id      <- o .: "request_id"
    lease_duration  <- o .: "lease_duration"
    warnings        <- o .:? "warnings" .!= []
    data_           <- o .: "data"
    pure VaultResponse {..}

instance {-# OVERLAPS #-} FromJSON (VaultResponse Auth) where
  parseJSON = withObject "VaultResponse" $ \o -> do
    lease_id       <- o .: "lease_id"
    renewable      <- o .: "renewable"
    request_id     <- o .: "request_id"
    lease_duration <- o .: "lease_duration"
    warnings       <- o .:? "warnings" .!= []
    data_          <- o .: "auth"
    pure VaultResponse {..}

instance {-# OVERLAPS #-} FromJSON (VaultResponse (WrapInfo a)) where
  parseJSON = withObject "VaultResponse" $ \o -> do
    lease_id       <- o .: "lease_id"
    renewable      <- o .: "renewable"
    request_id     <- o .: "request_id"
    lease_duration <- o .: "lease_duration"
    warnings       <- o .:? "warnings" .!= []
    data_          <- o .: "wrap_info"
    pure VaultResponse {..}


data VaultClientError
  = VaultClientError Text
  | VaultResponseError !Status Text Text LBS.ByteString
  deriving stock (Show)

instance Exception VaultClientError


mkVaultRequest
  :: Method
  -> [Text]
  -> Maybe LBS.ByteString
  -> VaultRequest a
mkVaultRequest meth path dat = VaultRequest
  { vaultRequestPath = path
  , vaultRequestQuery = mempty
  , vaultRequestMethod = meth
  , vaultRequestData = dat
  , vaultRequestWrapTTL = Nothing
  , vaultRequestCT = Nothing
  }

mkVaultRequest_ :: Method -> [Text] -> VaultRequest a
mkVaultRequest_ meth path = mkVaultRequest meth path Nothing


mkVaultWrite
  :: Method
  -> [Text]
  -> Maybe LBS.ByteString
  -> VaultWrite
mkVaultWrite meth path dat = VaultWrite
  { vaultWritePath = path
  , vaultWriteMethod = meth
  , vaultWriteData = dat
  }

mkVaultWrite_ :: Method -> [Text] -> VaultWrite
mkVaultWrite_ meth path = mkVaultWrite meth path Nothing

mkVaultWriteJSON
  :: ToJSON a
  => Method
  -> [Text]
  -> a
  -> VaultWrite
mkVaultWriteJSON meth path =
  mkVaultWrite meth path . Just . encode


mkVaultRequestJSON
  :: ToJSON a
  => Method
  -> [Text]
  -> a
  -> VaultRequest b
mkVaultRequestJSON meth path =
  mkVaultRequest meth path . Just . encode

methodList :: Method
methodList = "LIST"

vaultDeriveToJSON :: Name -> Q [Dec]
vaultDeriveToJSON = deriveToJSON defaultOptions
  { fieldLabelModifier = stripUS }

vaultDeriveFromJSON :: Name -> Q [Dec]
vaultDeriveFromJSON = deriveFromJSON defaultOptions
  { fieldLabelModifier = stripUS }

stripUS :: String -> String
stripUS [] = []
stripUS x@['_'] = x
stripUS xs = go xs
  where
    go [] = []
    go ['_'] = []
    go (x:xs) = x : go xs
