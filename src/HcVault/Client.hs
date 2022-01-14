{-# LANGUAGE BangPatterns        #-}
{-# LANGUAGE DefaultSignatures   #-}
{-# LANGUAGE DeriveFunctor       #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE ScopedTypeVariables #-}
module HcVault.Client
  ( VaultClient(..)
  , VaultToken(..)
  , mkVaultClient
  , vaultQuery
  , vaultWrite
  , vaultWrap
  , vaultUnwrap
  , vaultQueryIfFound
  , vaultList
  , vaultQuery_
  , vaultWrap_
  , MountPoint(..)
  , module Export
  ) where

import           Control.Monad
import           Data.Aeson (FromJSON (..), eitherDecode')
import qualified Data.ByteString.Builder as BL
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Map.Strict as Map
import           Data.Maybe (fromMaybe)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import           HcVault.Client.Core
import           Network.HTTP.Client as C
import           Network.HTTP.Types.Header
import           Network.HTTP.Types.Status
import           Network.HTTP.Types.URI
import           UnliftIO (throwIO, try)

import           HcVault.Client.Auth.AppRole as Export
import           HcVault.Client.Secrets.KV as Export
import           HcVault.Client.Secrets.PKI as Export
import           HcVault.Client.Sys.Auth as Export
import           HcVault.Client.Sys.Policies as Export
import           HcVault.Client.Sys.Secrets as Export
import           HcVault.Client.Sys.Wrapping as Export

data VaultClient = VaultClient
  { vaultClientToken   :: !(Maybe VaultToken)
  , vaultClientManager :: !C.Manager
  , vaultClientReq     :: !C.Request
  }

hXVaultRequest :: HeaderName
hXVaultRequest = "X-Vault-Request"

hXVaultWrapTTL :: HeaderName
hXVaultWrapTTL = "X-Vault-Wrap-TTL"

mkRequest :: VaultClient -> VaultRequest a -> Request
mkRequest VaultClient{..} VaultRequest{..} =
  vaultClientReq
  { C.path = LBS.toStrict . BL.toLazyByteString
             $ encodePath vaultRequestPath (queryTextToQuery vaultRequestQuery)
  , C.method = vaultRequestMethod
  , C.requestHeaders =
    addCT $ addTTL
    [ (hContentType, "application/json")
    , (hXVaultRequest, "true")
    , (hAuthorization,
       "Bearer " <> maybe mempty (Text.encodeUtf8 . unVaultToken) vaultClientToken)
    ]
  , C.requestBody = C.RequestBodyLBS $ fromMaybe mempty vaultRequestData
  }
  where
    addCT = maybe id (\v hs -> (hContentType, v):hs) vaultRequestCT
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
      , vaultRequestQuery = mempty
      , vaultRequestMethod = vaultWriteMethod
      , vaultRequestWrapTTL = Nothing
      , vaultRequestCT = Nothing
      }

vaultQuery
  :: FromJSON (VaultResponse a)
  => VaultClient
  -> VaultRequest a
  -> IO a
vaultQuery vc req = getData <$> vaultQuery_ vc req
  where
    getData VaultResponse{..} = data_

vaultQueryIfFound
  :: FromJSON (VaultResponse a)
  => VaultClient
  -> VaultRequest a
  -> IO (Maybe a)
vaultQueryIfFound vc req = do
  r <- try $ vaultQuery vc req
  case r of
    Left e@(VaultResponseError st _ _ _)
      | st == status404 -> pure Nothing
      | otherwise -> throwIO e
    Left e -> throwIO e
    Right r -> pure (Just r)

vaultList
  :: FromJSON a
  => VaultClient
  -> VaultRequest (KeyList a)
  -> IO [a]
vaultList vc = fmap toRes . vaultQueryIfFound vc
  where
    toRes Nothing = []
    toRes (Just (KeyList x)) = x

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
  c <- mkVaultClient m "http://localhost:8200" (Just "s.OW4ktA0EN5hwDBqrTCPWTpvR")
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
  wi@WrapInfo{..} <- vaultWrap c 400 $ appRoleLoginAt "xxx" role_id secret_id
  print =<< vaultUnwrap c token
  print wi
  wi <- vaultWrap c 3600 $ appRoleGenerateSecretIdAt "xxx" "foo" mkAppRoleGenerateSecretId
  vaultWrite c $ appRoleTidyTokensAt "xxx"
  let WrapInfo{..} = wi
--  print <=< vaultQuery c $ wrappingUnwrap token
  print =<< vaultUnwrap c token
  WrapInfo{..} <- vaultQuery c $ wrappingWrap 300 (Map.fromList [("a","b")])
  print <=< vaultQuery c $ wrappingLookup token
  WrapInfo {..} <- vaultQuery c $ wrappingRewrap 300 token
  print <=< vaultQuery c $ wrappingUnwrap token
  print <=< vaultQuery c $ listSecretsEngineMounts
  vaultWrite c $ disableSecretsEngine "pki-logging"
  vaultWrite c $ enableSecretsEngine "pki-logging" (mkSecretsEngineCreate "pki")
  print <=< vaultQuery c $ readSecretsEngineMount "pki-logging"
  vaultWrite c $ tuneSecretsEngineMount "pki-logging" mkSecretsEngineConfig
  -- Does not work?
  --print <=< vaultQuery c $ secretsEngineGetInfo "pki-logging"
  vaultWrite c $ disableSecretsEngine "pki-logging"

