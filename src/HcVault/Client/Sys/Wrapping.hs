{-# LANGUAGE TemplateHaskell #-}
module HcVault.Client.Sys.Wrapping
  ( wrappingUnwrap
  , wrappingLookup
  , wrappingRewrap
  , wrappingWrap
  ) where

import           Data.Aeson (FromJSON, encode, pairs, (.=))
import           Data.Aeson.Encoding (encodingToLazyByteString)
import           Data.Map.Strict (Map)
import           Data.Text (Text)
import           Data.Time (UTCTime)

import           HcVault.Client.Core

wrappingUnwrap
  :: WrappingToken a
  -> VaultRequest a
wrappingUnwrap tok =
  mkVaultRequest methodPost
  ["v1", "sys", "wrapping", "unwrap"]
  (Just $ tokenPayload tok)

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
  -> VaultRequest WrappingInfo
wrappingLookup tok =
  mkVaultRequest methodPost
  ["v1", "sys", "wrapping", "lookup"]
  (Just $ tokenPayload tok)

wrappingRewrap
  :: Int
  -> WrappingToken a
  -> VaultRequest (WrapInfo a)
wrappingRewrap ttl tok =
  r { vaultRequestWrapTTL = Just ttl }
  where
    r = mkVaultRequest methodPost
      ["v1", "sys", "wrapping", "rewrap"]
      (Just $ tokenPayload tok)

wrappingWrap
  :: Int
  -> Map Text Text
  -> VaultRequest (WrapInfo (Map Text Text))
wrappingWrap ttl v =
  r { vaultRequestWrapTTL = Just ttl }
  where
    r = mkVaultRequest methodPost
      ["v1", "sys", "wrapping", "wrap"]
      (Just $ encode v)

concat <$> sequence [
  vaultDeriveFromJSON ''WrappingInfo
 ]
