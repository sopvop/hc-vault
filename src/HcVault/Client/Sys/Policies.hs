{-# LANGUAGE TemplateHaskell #-}
module HcVault.Client.Sys.Policies
  ( listAclPolicies
  , readAclPolicyText
  , putAclPolicyText
  , AclPolicy(..)
  , PolicyName(..)
  ) where

import           Data.Aeson (pairs, (.=))
import           Data.Aeson.Encoding (encodingToLazyByteString)
import           Data.Text (Text)
import           GHC.Generics (Generic)
import           HcVault.Client.Core

-- | This endpoint lists all configured ACL policies.
listAclPolicies :: VaultRequest (KeyList PolicyName)
listAclPolicies =
  mkVaultRequest_ methodList
  ["v1", "sys", "policies", "acl"]


data AclPolicy = AclPolicy
  { name   :: PolicyName
  , policy :: Text
  }
  deriving stock (Eq, Ord, Show, Generic)

-- | This endpoint retrieves information about the named ACL policy.
readAclPolicyText :: PolicyName -> VaultRequest AclPolicy
readAclPolicyText pn =
  mkVaultRequest_ methodList
  ["v1", "sys", "policies", "acl", unPolicyName pn]


-- | This endpoint retrieves information about the named ACL policy.
putAclPolicyText
  :: PolicyName
  -> Text
  -> VaultWrite
putAclPolicyText pn =
  mkVaultWrite methodPost
  ["v1", "sys", "policies", "acl", unPolicyName pn]
  . Just . encodingToLazyByteString . pairs . ("policy" .=)


concat <$> sequence
  [ vaultDeriveFromJSON ''AclPolicy
  , vaultDeriveToJSON ''AclPolicy
  ]
