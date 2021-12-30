{-# LANGUAGE TemplateHaskell #-}
module HcVault.Client.Sys.Wrapping
  ( wrappingUnwrap
  , wrappingLookup
  , wrappingRewrap
  , wrappingWrap
  ) where

import           Data.Aeson (FromJSON (..), encode, pairs, (.=))
import           Data.Aeson.Encoding (encodingToLazyByteString)
import qualified Data.ByteString.Lazy as LBS
import           Data.Map.Strict (Map)
import           Data.Text (Text)
import           Data.Time (UTCTime)

import           HcVault.Client.Core

wrappingUnwrap
  :: FromJSON a
  => WrappingToken a
  -> VaultQuery a
wrappingUnwrap tok =
  mkVaultQuery methodPost
  (pathV1 ["sys", "wrapping", "unwrap"])
  (Just $ tokenPayload tok)
  parseJSON

tokenPayload :: WrappingToken a -> LBS.ByteString
tokenPayload tok =
  encodingToLazyByteString . pairs
  $ "token" .= getWrappingToken tok


data WrappingInfo = WrappingInfo
  { creation_ttl  :: Int
  , creation_time :: UTCTime
  , creation_path :: Text
  }
  deriving stock (Eq, Show)

wrappingLookup
  :: WrappingToken a
  -> VaultQuery WrappingInfo
wrappingLookup tok =
  mkVaultQuery methodPost
  (pathV1 ["sys", "wrapping", "lookup"])
  (Just $ tokenPayload tok)
  parseJSON

wrappingRewrap
  :: Int
  -> WrappingToken a
  -> VaultWrap a
wrappingRewrap ttl tok = VaultWrap
  { _vaultWrapMethod = methodPost
  , _vaultWrapPath = pathV1 ["sys", "wrapping", "rewrap"]
  , _vaultWrapData = Just $ tokenPayload tok
  , _vaultWrapWrapTTL = Just ttl
  }

wrappingWrap
  :: Int
  -> Map Text Text
  -> VaultWrap (WrapResponse (QueryResponse (Map Text Text)))
wrappingWrap ttl v = VaultWrap
  { _vaultWrapMethod = methodPost
  , _vaultWrapPath = pathV1 ["sys", "wrapping", "wrap"]
  , _vaultWrapData = Just $ encode v
  , _vaultWrapWrapTTL = Just ttl
  }

concat <$> sequence [
  vaultDeriveFromJSON ''WrappingInfo
 ]
