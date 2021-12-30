{-# LANGUAGE BangPatterns        #-}
{-# LANGUAGE DefaultSignatures   #-}
{-# LANGUAGE DeriveFunctor       #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE ScopedTypeVariables #-}
module HcVault.Client
  (
  ) where

import           Control.Monad
import           Data.Aeson (FromJSON (..), ToJSON (..), eitherDecode')
--    (Encoding, FromJSON (..), ToJSON, Value, decode', eitherDecode', encode,
--    withObject, (.=))
import           Data.Aeson.Encoding (encodingToLazyByteString)
import           Data.Aeson.Types (Parser, Value, parseEither)
import qualified Data.ByteString.Builder as BL
import qualified Data.ByteString.Lazy as LBS
import           Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import           Data.Maybe (fromMaybe)
import           Data.String (IsString)
import           Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import           HcVault.Client.Core
import           Network.HTTP.Client as C
import           Network.HTTP.Types.Header
import           Network.HTTP.Types.Method
import           Network.HTTP.Types.Status
import           Network.HTTP.Types.URI
import           UnliftIO (Exception, throwIO)

import           HcVault.Client.Auth.AppRole
import           HcVault.Client.Sys.Auth
import           HcVault.Client.Sys.Secrets
import           HcVault.Client.Sys.Wrapping

data VaultClient = VaultClient
  { vaultClientToken   :: !(Maybe VaultToken)
  , vaultClientManager :: !C.Manager
  , vaultClientReq     :: !C.Request
  }

hXVaultToken :: HeaderName
hXVaultToken = "X-Vault-Token"

hXVaultRequest :: HeaderName
hXVaultRequest = "X-Vault-Request"

hXVaultWrapTTL :: HeaderName
hXVaultWrapTTL = "X-Vault-Wrap-TTL"

mkRequest :: VaultClient -> VaultRequest a -> Request
mkRequest VaultClient{..} VaultRequest{..} =
  vaultClientReq
  { C.path = LBS.toStrict . BL.toLazyByteString
             $ encodePath vaultRequestPath mempty
  , C.method = vaultRequestMethod
  , C.requestHeaders =
    addTTL
    [ (hContentType, "application/json")
    , (hAuthorization,
       "Bearer " <> maybe mempty (Text.encodeUtf8 . unVaultToken) vaultClientToken)
    ]
  , C.requestBody = C.RequestBodyLBS $ fromMaybe mempty vaultRequestData
  }
  where
    addTTL = maybe id (\v hs -> (hXVaultWrapTTL, bsInt v):hs) vaultRequestWrapTTL
    bsInt = LBS.toStrict . BL.toLazyByteString . BL.intDec

makeVaultRequest :: VaultClient -> VaultRequest a -> IO LBS.ByteString
makeVaultRequest vc@VaultClient{vaultClientManager} req = do
  r <- C.httpLbs r vaultClientManager
  let body = C.responseBody r
      st = C.responseStatus r
  if  | statusCode st >= 200 && statusCode st < 300 ->  pure body
      | otherwise                                   -> throwBadRequest st body
  where
    throwBadRequest st body
      | statusCode st >= 400 = throwIO $ VaultResponseError st m tp body
      | otherwise = throwIO $ VaultResponseError st m tp mempty
    r = mkRequest vc req
    tp = Text.decodeLatin1 $ C.path r
    m = Text.decodeLatin1 $ C.method r

vaultQuery_
  :: FromJSON (VaultResponse a)
  => VaultClient
  -> VaultRequest a
  -> IO (VaultResponse a)
vaultQuery_ vc req = do
  makeVaultRequest vc req >>= either (throwIO . VaultClientError . Text.pack) pure
    . eitherDecode'


vaultWrite :: VaultClient -> VaultWrite -> IO ()
vaultWrite vc VaultWrite{..} = () <$ makeVaultRequest vc req
  where
    req = VaultRequest
      { vaultRequestData = vaultWriteData
      , vaultRequestPath = vaultWritePath
      , vaultRequestMethod = vaultWriteMethod
      , vaultRequestWrapTTL = Nothing
      }

vaultQuery
  :: FromJSON (VaultResponse a)
  => VaultClient
  -> VaultRequest a
  -> IO a
vaultQuery vc req = getData <$> vaultQuery_ vc req
  where
    getData VaultResponse{..} = data_

vaultWrap_
  :: VaultClient
  -> Int
  -> VaultRequest a
  -> IO (VaultResponse (WrapInfo a))
vaultWrap_ vc ttl VaultRequest{..} = vaultQuery_ vc wreq
  where
    wreq = VaultRequest { vaultRequestWrapTTL = Just ttl, ..}

vaultWrap
  :: VaultClient
  -> Int
  -> VaultRequest a
  -> IO (WrapInfo a)
vaultWrap vc ttl req = getData <$> vaultWrap_ vc ttl req
  where
    getData VaultResponse{..} = data_

vaultUnwrap_
  :: (FromJSON (VaultResponse a))
  => VaultClient
  -> WrappingToken a
  -> IO (VaultResponse a)
vaultUnwrap_ vc token = vaultQuery_ vc $ wrappingUnwrap token

vaultUnwrap
  :: FromJSON (VaultResponse a)
  => VaultClient
  -> WrappingToken a
  -> IO a
vaultUnwrap vc token = getData <$> vaultUnwrap_ vc token
  where
    getData VaultResponse{..} = data_


mkVaultClient
  :: Manager
  -> String -- ^ "Vault URL"
  -> Maybe VaultToken
  -> IO VaultClient
mkVaultClient manager host token = do
  !h <- C.parseRequest host
  pure $ VaultClient token manager h

foo = do
  m <- newManager defaultManagerSettings
  c <- mkVaultClient m "http://localhost:8200" (Just "s.rTfinVptoxok9trPZ349ftRX")
  vaultWrite c $ disableAuthMethod "xxx"
  vaultWrite c $ enableAuthMethod "xxx" $ mkAuthMethodEnable "approle"
  tune <- vaultQuery c $ readAuthMethodTuning "xxx"
  print tune
  vaultWrite c $ tuneAuthMethod "xxx" $ (mkAuthMethodTuning :: AuthMethodTuning)
    { max_lease_ttl = 100
    }
  tune <- vaultQuery c $ readAuthMethodTuning "xxx"
  print tune
  vaultWrite c $ appRoleCreateRoleAt "xxx" "foo" mkAppRole
  print <=< vaultQuery c $ appRoleListRolesAt "xxx"
  g <- vaultQuery c $ appRoleGenerateSecretIdAt "xxx" "foo"
    (mkAppRoleGenerateSecretId :: AppRoleGenerateSecretId)
    { metadata = Map.fromList [("key", "val")]
    }
  AppRoleRoleId {..} <- vaultQuery c $ appRoleReadRoleIdAt "xxx" "foo"
  let AppRoleGeneratedSecretId{..} = g
  print $ unAppRoleSecretId secret_id
  print secret_id_accessor
  print <=< vaultQuery c $ appRoleListSecretIdAccessorsAt "xxx" "foo"
  print <=< vaultQuery c $ readAppRoleSecretIdInfoAt "xxx" "foo" secret_id
  print <=< vaultQuery c $ readAppRoleSecretIdAccessorInfoAt "xxx" "foo" secret_id_accessor
  print <=< vaultQuery c $ appRoleLoginAt "xxx" role_id secret_id
  wi <- vaultWrap c 3600 $ appRoleGenerateSecretIdAt "xxx" "foo" mkAppRoleGenerateSecretId
  vaultWrite c $ appRoleTidyTokensAt "xxx"
  let WrapInfo{..} = wi
--  print <=< vaultQuery c $ wrappingUnwrap token
  print =<< vaultUnwrap c token
  WrapInfo{..} <- vaultQuery c $ wrappingWrap 300 (Map.fromList [("a","b")])
  print <=< vaultQuery c $ wrappingLookup token
  WrapInfo {..} <- vaultQuery c $ wrappingRewrap 300 token
  print <=< vaultQuery c $ wrappingUnwrap token
  print <=< vaultQuery c $ secretsEngineListMounts
  vaultWrite c $ secretsEngineDisable "pki-logging"
  vaultWrite c $ secretsEngineCreate "pki-logging" (mkSecretsEngineCreate "pki")
  print <=< vaultQuery c $ secretsEngineReadMount "pki-logging"
  vaultWrite c $ secretsEngineTuneMount "pki-logging" mkSecretsEngineConfig
  -- Does not work?
  --print <=< vaultQuery c $ secretsEngineGetInfo "pki-logging"
  vaultWrite c $ secretsEngineDisable "pki-logging"

