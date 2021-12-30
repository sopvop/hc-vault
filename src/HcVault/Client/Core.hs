{-# LANGUAGE DeriveFunctor     #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE GADTs             #-}
module  HcVault.Client.Core
  ( VaultToken(..)
  , VaultQuery (..)
  , VaultWrite(..)
  , VaultAuth(..)
  , VaultWrap(..)
  , WrappingToken(..)
  , VaultRequest(..)
  , Expects (..)
  , NoData (..)
  , mkVaultQuery
  , mkVaultQuery_
  , mkVaultQueryJSON
  , mkVaultQueryJSON_
  , mkVaultWrite
  , mkVaultWriteJSON
  , QueryResponse(..)
  , AuthResponse(..)
  , WrapResponse(..)
  , VaultResponse(..)
  , vaultResponseToAuth
  , vaultResponseToQuery
  , vaultResponseToWrap
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
  , vaultDeriveToJSON
  , vaultDeriveFromJSON
  , VaultPath(..)
  , pathV1
  , pathMatches
  , eitherDecode'
  ) where

import           Control.Exception (Exception)
import           Data.Aeson
    (FromJSON (..), FromJSONKey (..), FromJSONKeyFunction (..), ToJSON (..),
    Value, eitherDecode', encode, withObject, (.!=), (.:), (.:?))
import           Data.Aeson.TH
    (Options (..), defaultOptions, deriveFromJSON, deriveToJSON)
import           Data.Aeson.Types (Parser)
import qualified Data.ByteString.Lazy as LBS
import           Data.Coerce (coerce)
import           Data.List.NonEmpty (NonEmpty (..))
import qualified Data.List.NonEmpty as NonEmpty
import           Data.Map.Strict (Map)
import           Data.String (IsString)
import           Data.Text (Text)
import qualified Data.Text as Text
import           Data.Time (UTCTime)
import           Language.Haskell.TH.Syntax (Dec, Name, Q)
import           Network.HTTP.Types.Method
import           Network.HTTP.Types.Status

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

newtype VaultPath = VaultPath
  { unVaultPath :: NonEmpty Text }
  deriving stock (Eq, Ord, Show)

pathV1 :: [Text] -> VaultPath
pathV1 ps = VaultPath ("v1" :| ps)

pathMatches :: VaultPath -> VaultPath -> Bool
pathMatches (VaultPath a) (VaultPath b) =
  NonEmpty.tail a == NonEmpty.tail b

data NoData = NoData
  deriving stock (Eq, Ord, Show)

instance FromJSON NoData where
  parseJSON _ = pure NoData

data Expects a where
  Expects :: FromJSON a => Expects a
  ExpectsNoContent :: Expects ()

data VaultWrite = VaultWrite
  { _vaultWriteMethod :: !Method
  , _vaultWritePath   :: !VaultPath
  , _vaultWriteData   :: !(Maybe LBS.ByteString)
  }

data VaultQuery a = VaultQuery
  { _vaultQueryMethod  :: !Method
  , _vaultQueryPath    :: !VaultPath
  , _vaultQueryData    :: !(Maybe LBS.ByteString)
  , _vaultQueryResp    :: !(Value -> Parser a)
  , _vaultQueryWrapTTL :: !(Maybe Int)
  }

data VaultWrap a = VaultWrap
  { _vaultWrapMethod  :: !Method
  , _vaultWrapPath    :: !VaultPath
  , _vaultWrapData    :: !(Maybe LBS.ByteString)
  , _vaultWrapWrapTTL :: !(Maybe Int)
  }

data VaultAuth = VaultAuth
  { _vaultAuthMethod  :: !Method
  , _vaultAuthPath    :: !VaultPath
  , _vaultAuthData    :: !(Maybe LBS.ByteString)
  , _vaultAuthWrapTTL :: !(Maybe Int)
  }

data VaultRequest = VaultRequest
  { _vaultRequestMethod  :: !Method
  , _vaultRequestPath    :: !VaultPath
  , _vaultRequestData    :: !(Maybe LBS.ByteString)
  , _vaultRequestWrapTTL :: !(Maybe Int)
  }

newtype LeaseId = LeaseId { unLeaseId :: Text }
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON)

newtype RequestId = RequestId { unRequestId :: Text }
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON)

newtype AuthAccessor = AuthAccessor { unAuthAccessor :: Text }
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON)

newtype PolicyName = PolicyName { unRequestId :: Text }
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON)

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

data QueryResponse a = QueryResponse
  { lease_id       :: !LeaseId
  , renewable      :: !Bool
  , request_id     :: !RequestId
  , lease_duration :: !Int
  , warnings       :: ![Text]
  , data_          :: !a
  }
  deriving stock (Show, Eq, Functor, Foldable, Traversable)

data VaultResponse = VaultResponse
  { lease_id       :: !LeaseId
  , renewable      :: !Bool
  , request_id     :: !RequestId
  , lease_duration :: !Int
  , warnings       :: ![Text]
  , auth           :: !(Maybe Auth)
  , wrap_info      :: !(Maybe (WrapInfo ()))
  , data_          :: !(Maybe Value)
  }
  deriving stock (Show, Eq)


data AuthResponse = AuthResponse
  { lease_id       :: !LeaseId
  , renewable      :: !Bool
  , request_id     :: !RequestId
  , lease_duration :: !Int
  , warnings       :: ![Text]
  , auth           :: !Auth
  }
  deriving stock (Show, Eq)


data WrapResponse a = WrapResponse
  { lease_id       :: !LeaseId
  , renewable      :: !Bool
  , request_id     :: !RequestId
  , lease_duration :: !Int
  , warnings       :: ![Text]
  , wrap_info      :: !(WrapInfo a)
  }
  deriving stock (Show, Eq)

instance FromJSON VaultResponse where
  parseJSON = withObject "VaultResponse" $ \o -> do
    lease_id        <- o .: "lease_id"
    renewable       <- o .: "renewable"
    request_id      <- o .: "request_id"
    lease_duration  <- o .: "lease_duration"
    warnings        <- o .:? "warnings" .!= []
    data_           <- o .:? "data"
    auth            <- o .:? "auth"
    wrap_info       <- o .:? "wrap_info"
    pure VaultResponse {..}

instance FromJSON a => FromJSON (QueryResponse a) where
  parseJSON = withObject "QueryResponse" $ \o -> do
    lease_id        <- o .: "lease_id"
    renewable       <- o .: "renewable"
    request_id      <- o .: "request_id"
    lease_duration  <- o .: "lease_duration"
    warnings        <- o .:? "warnings" .!= []
    data_           <- o .: "data"
    pure QueryResponse {..}

instance FromJSON AuthResponse where
  parseJSON = withObject "AuthResponse" $ \o -> do
    lease_id       <- o .: "lease_id"
    renewable      <- o .: "renewable"
    request_id     <- o .: "request_id"
    lease_duration <- o .: "lease_duration"
    warnings       <- o .:? "warnings" .!= []
    auth           <- o .: "auth"
    pure AuthResponse {..}

instance FromJSON (WrapResponse a) where
  parseJSON = withObject "WrapResponse" $ \o -> do
    lease_id       <- o .: "lease_id"
    renewable      <- o .: "renewable"
    request_id     <- o .: "request_id"
    lease_duration <- o .: "lease_duration"
    warnings       <- o .:? "warnings" .!= []
    wrap_info      <- o .: "wrap_info"
    pure WrapResponse {..}

vaultResponseToAuth :: VaultResponse -> Maybe AuthResponse
vaultResponseToAuth VaultResponse{..} =
  case auth of
    Nothing -> Nothing
    Just a -> Just AuthResponse{auth = a, ..}

vaultResponseToQuery :: VaultResponse -> Maybe (QueryResponse Value)
vaultResponseToQuery VaultResponse{..} =
  case data_ of
    Nothing -> Nothing
    Just d -> Just QueryResponse{data_ = d, ..}

vaultResponseToWrap :: VaultResponse -> Maybe (WrapResponse ())
vaultResponseToWrap VaultResponse{..} =
  case wrap_info of
    Nothing -> Nothing
    Just w -> Just WrapResponse{wrap_info = w, ..}

data VaultClientError
  = VaultClientError Text
  | VaultResponseParseError VaultPath Text
  | VaultResponseError !Status Text Text LBS.ByteString
  deriving stock (Show)

instance Exception VaultClientError


mkVaultWrite
  :: Method
  -> VaultPath
  -> Maybe LBS.ByteString
  -> VaultWrite
mkVaultWrite meth path dat = VaultWrite
  { _vaultWritePath = path
  , _vaultWriteMethod = meth
  , _vaultWriteData = dat
  }

mkVaultWriteJSON
  :: ToJSON a
  => Method
  -> VaultPath
  -> a
  -> VaultWrite
mkVaultWriteJSON meth path dat
 = mkVaultWrite meth path . Just $ encode dat

mkVaultQuery
  :: Method
  -> VaultPath
  -> Maybe LBS.ByteString
  -> (Value -> Parser a)
  -> VaultQuery a
mkVaultQuery meth path dat dec = VaultQuery
  { _vaultQueryPath = path
  , _vaultQueryMethod = meth
  , _vaultQueryData = dat
  , _vaultQueryResp = dec
  , _vaultQueryWrapTTL = Nothing
  }

mkVaultQuery_
  :: Method
  -> VaultPath
  -> (Value -> Parser a)
  -> VaultQuery a
mkVaultQuery_ meth path dec =
  mkVaultQuery meth path Nothing dec

mkVaultQueryJSON
  :: ToJSON a
  => FromJSON b
  => Method
  -> VaultPath
  -> a
  -> VaultQuery b
mkVaultQueryJSON meth path dat = VaultQuery
  { _vaultQueryPath = path
  , _vaultQueryMethod = meth
  , _vaultQueryData = Just $! encode dat
  , _vaultQueryResp = parseJSON
  , _vaultQueryWrapTTL = Nothing
  }

mkVaultQueryJSON_
  :: FromJSON a
  => Method
  -> VaultPath
  -> VaultQuery a
mkVaultQueryJSON_ meth path = VaultQuery
  { _vaultQueryPath = path
  , _vaultQueryMethod = meth
  , _vaultQueryData = Nothing
  , _vaultQueryResp = parseJSON
  , _vaultQueryWrapTTL = Nothing
  }


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
