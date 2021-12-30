{-# LANGUAGE BangPatterns        #-}
{-# LANGUAGE DeriveFunctor       #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE ScopedTypeVariables #-}
module HcVault.Client
  (
  ) where

import           Control.Monad
import           Data.Aeson (ToJSON (..), eitherDecode')
import           Data.Aeson.Types (parseEither)
--    (Encoding, FromJSON (..), ToJSON, Value, decode', eitherDecode', encode,
--    withObject, (.=))
import           Data.Aeson.Encoding (encodingToLazyByteString)
import qualified Data.ByteString.Builder as BL
import qualified Data.ByteString.Lazy as LBS
import           Data.Coerce (coerce)
import           Data.Functor.Const
import qualified Data.List.NonEmpty as NonEmpty
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

mkRequest :: VaultClient -> VaultRequest -> Request
mkRequest VaultClient{..} VaultRequest{..} =
  vaultClientReq
  { C.path = LBS.toStrict . BL.toLazyByteString
             $ encodePath (NonEmpty.toList . unVaultPath $ _vaultRequestPath) mempty
  , C.method = _vaultRequestMethod
  , C.requestHeaders =
    addTTL
    [ (hContentType, "application/json")
    , (hAuthorization,
       "Bearer " <> maybe mempty (Text.encodeUtf8 . unVaultToken) vaultClientToken)
    ]
  , C.requestBody = C.RequestBodyLBS $ fromMaybe mempty _vaultRequestData
  }
  where
    addTTL = maybe id (\v hs -> (hXVaultWrapTTL, bsInt v):hs) _vaultRequestWrapTTL
    bsInt = LBS.toStrict . BL.toLazyByteString . BL.intDec

makeVaultRequest :: VaultClient -> VaultRequest -> IO (Maybe VaultResponse)
makeVaultRequest vc@VaultClient{vaultClientManager} req = do
  r <- C.httpLbs r vaultClientManager
  let body = C.responseBody r
      st = C.responseStatus r
  if | st == noContent204 -> pure Nothing
     | st == ok200 || st == accepted202 ->
         either (throwIO . VaultClientError . Text.pack) pure
           $ eitherDecode' body
     | otherwise -> throwBadRequest st body
  where
    throwBadRequest st body
      | statusCode st >= 400 = throwIO $ VaultResponseError st m tp body
      | otherwise = throwIO $ VaultResponseError st m tp mempty
    r = mkRequest vc req
    tp = Text.decodeLatin1 $ C.path r
    m = Text.decodeLatin1 $ C.method r

vaultWrite :: VaultClient -> VaultWrite -> IO ()
vaultWrite vc VaultWrite{..} = () <$ makeVaultRequest vc req
  where
    req = VaultRequest
      { _vaultRequestMethod = _vaultWriteMethod
      , _vaultRequestData = _vaultWriteData
      , _vaultRequestPath = _vaultWritePath
      , _vaultRequestWrapTTL = Nothing
      }

vaultQuery_ :: VaultClient -> VaultQuery a -> IO (QueryResponse a)
vaultQuery_ vc VaultQuery{..} =
    makeVaultRequest vc req >>= maybe noCont parseData
  where
    parseData VaultResponse{..} = do
      d <- maybe noResp pure data_
      case parseEither _vaultQueryResp d of
        Left e -> throwIO $ VaultResponseParseError _vaultQueryPath (Text.pack e)
        Right r -> pure $ QueryResponse{data_ = r, ..}

    noResp = throwIO $ VaultResponseParseError _vaultQueryPath "No content returned by server"
    noCont = throwIO $ VaultResponseParseError _vaultQueryPath "Server returned no content"
    req = VaultRequest
      { _vaultRequestMethod = _vaultQueryMethod
      , _vaultRequestData = _vaultQueryData
      , _vaultRequestPath = _vaultQueryPath
      , _vaultRequestWrapTTL = Nothing
      }

vaultQuery :: VaultClient -> VaultQuery a -> IO a
vaultQuery vc q = getData <$> vaultQuery_ vc q
  where
    getData QueryResponse{..} = data_


vaultAuth_ :: VaultClient -> VaultAuth -> IO AuthResponse
vaultAuth_ vc VaultAuth{..} =
    makeVaultRequest vc req >>= maybe noCont parseData
  where
    parseData VaultResponse{..} = maybe noAuth (\a -> pure AuthResponse{auth=a, ..}) auth
    noAuth = throwIO $ VaultResponseParseError _vaultAuthPath "Server returned no auth"
    noCont = throwIO $ VaultResponseParseError _vaultAuthPath "Server returned no content"
    req = VaultRequest
      { _vaultRequestMethod = _vaultAuthMethod
      , _vaultRequestData = _vaultAuthData
      , _vaultRequestPath = _vaultAuthPath
      , _vaultRequestWrapTTL = Nothing
      }

vaultAuth :: VaultClient -> VaultAuth -> IO Auth
vaultAuth vc q = getAuth <$> vaultAuth_ vc q
  where
    getAuth AuthResponse{..} = auth

parseWrapResponse p Nothing =
  throwIO $ VaultResponseParseError  p "Server returned no content"
parseWrapResponse p (Just VaultResponse{..}) =
  maybe noWrap (\w -> pure WrapResponse {wrap_info=coerce w,..}) wrap_info
  where
    noWrap = throwIO $ VaultResponseParseError p "Server returned no vault_info"


vaultWrap_
  :: VaultClient
  -> Int
  -> VaultWrap a
  -> IO (WrapResponse a)
vaultWrap_ vc ttl VaultQuery{..} =
    makeVaultRequest vc req >>= parseWrapResponse _vaultQueryPath
  where
    req = VaultRequest
      { _vaultRequestMethod = _vaultQueryMethod
      , _vaultRequestData = _vaultQueryData
      , _vaultRequestPath = _vaultQueryPath
      , _vaultRequestWrapTTL = Just ttl
      }


vaultWrapQuery_
  :: VaultClient
  -> Int
  -> VaultQuery a
  -> IO (WrapResponse (QueryResponse a))
vaultWrapQuery_ vc ttl VaultQuery{..} =
    makeVaultRequest vc req >>= parseWrapResponse _vaultQueryPath
  where
    req = VaultRequest
      { _vaultRequestMethod = _vaultQueryMethod
      , _vaultRequestData = _vaultQueryData
      , _vaultRequestPath = _vaultQueryPath
      , _vaultRequestWrapTTL = Just ttl
      }

vaultWrapQuery
  :: VaultClient
  -> Int
  -> VaultQuery a
  -> IO (WrapInfo (QueryResponse a))
vaultWrapQuery vc ttl q =
  getWrap <$> vaultWrapQuery_ vc ttl q
  where
    getWrap WrapResponse{..} = wrap_info

vaultWrapAuth_
  :: VaultClient
  -> Int
  -> VaultAuth
  -> IO (WrapResponse AuthResponse)
vaultWrapAuth_ vc ttl VaultAuth{..} =
    makeVaultRequest vc req >>= parseWrapResponse _vaultAuthPath
  where
    req = VaultRequest
      { _vaultRequestMethod = _vaultAuthMethod
      , _vaultRequestData = _vaultAuthData
      , _vaultRequestPath = _vaultAuthPath
      , _vaultRequestWrapTTL = Just ttl
      }

vaultWrapAuth
  :: VaultClient
  -> Int
  -> VaultAuth
  -> IO (WrapInfo AuthResponse)
vaultWrapAuth vc ttl q =
  getWrap <$> vaultWrapAuth_ vc ttl q
  where
    getWrap WrapResponse{..} = wrap_info


vaultWrapValue
  :: VaultClient
  -> Int
  -> Map Text Text
  -> IO (WrapInfo (QueryResponse (Map Text Text)))
vaultWrapValue vc ttl val =
    getWrap <$> vaultWrap vc (wrappingWrap ttl val)
  where
    getWrap WrapResponse{..} = wrap_info

mkVaultClient
  :: Manager
  -> String -- ^ "Vault URL"
  -> Maybe VaultToken
  -> IO VaultClient
mkVaultClient manager host token = do
  !h <- C.parseRequest host
  pure $ VaultClient token manager h

{-
vaultRequest :: VaultClient -> VaultRequest a -> IO a
vaultRequest = makeVaultRequest



foo = do
  m <- newManager defaultManagerSettings
  c <- mkVaultClient m "http://localhost:8200" (Just "s.lNZy9UolVZ7B4sSI7w5F8YeT")
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
  print <=< vaultAuth c $ appRoleLoginAt "xxx" role_id secret_id
  wi <- vaultWrapResponse c 3600 $ appRoleGenerateSecretIdAt "xxx" "foo" mkAppRoleGenerateSecretId
  vaultWrite' c $ appRoleTidyTokensAt "xxx"
  let WrapInfo{..} = wi
  print <=< vaultQuery c $ wrappingUnwrap token
  WrapInfo{..} <- vaultWrap c $ wrappingWrap 300 (Map.fromList [("a","b")])
  print <=< vaultQuery c $ wrappingLookup token
  WrapInfo {..} <-vaultWrap c $ wrappingRewrap 300 token
  print <=< vaultQuery c $ wrappingUnwrap token
  print <=< vaultQuery c $ secretsEngineListMounts
  vaultWrite c $ secretsEngineDisable "pki-logging"
  vaultWrite c $ secretsEngineCreate "pki-logging" (mkSecretsEngineCreate "pki")
  print <=< vaultQuery c $ secretsEngineReadMount "pki-logging"
  vaultWrite c $ secretsEngineTuneMount "pki-logging" mkSecretsEngineConfig
  -- Does not work?
  -- print <=< vaultQuery c $ secretsEngineGetInfo "pki-logging"
  vaultWrite c $ secretsEngineDisable "pki-logging"
-}
