{-# LANGUAGE TemplateHaskell #-}
module HcVault.Client.Secrets.PKI
  ( -- ** Reading cerificates
    readPkiCertificateAt
  , readPkiCertificate
  , listPkiCertificatesAt
  , listPkiCertificates
  , PkiCertificate (..)
  , CertificateSerial(..)
    -- ** Setting up CRL
  , readPkiCrlConfigurationAt
  , readPkiCrlConfiguration
  , setPkiCrlConfigurationAt
  , setPkiCrlConfiguration
  , PkiCrlConfiguration(..)
    -- ** Setting up URLs
  , readPkiUrlsAt
  , readPkiUrls
  , setPkiUrlsAt
  , setPkiUrls
  , PkiUrls(..)
  , mkPkiUrls
    -- ** Issuing certificates
  , issuePkiCertificateAt
  , issuePkiCertificate
  , PkiCertificateParams(..)
  , mkPkiCertificateParams
  , PkiIssuedCertificate(..)
  , PkiPrivateKey(..)
  , revokePkiCertificateAt
  , revokePkiCertificate
  , PkiRevocationTime(..)
    -- ** Managing roles
  , createPkiRoleAt
  , createPkiRole
  , readPkiRoleAt
  , readPkiRole
  , deletePkiRoleAt
  , deletePkiRole
  , PkiRole(..)
  , mkPkiRole
  , PkiRoleName(..)
    -- ** Managing root certificate
  , generatePkiRootCertificateAt
  , generatePkiRootCertificate
  , generateExportedPkiRootCertificateAt
  , generateExportedPkiRootCertificate
  , deletePkiRootCertificateAt
  , deletePkiRootCertificate
  , PkiIssuedRootCertificate(..)
  , PkiRootCertificateParams(..)
  , mkPkiRootCertificateParams
  ) where

import           Data.Aeson
    (FromJSON (..), ToJSON, pairs, withObject, (.:), (.=))
import           Data.Aeson.Encoding (encodingToLazyByteString)
import           Data.Coerce (coerce)
import           Data.String (IsString)
import           Data.Text (Text)
import           GHC.Generics (Generic)

import           HcVault.Client.Core

newtype PkiCertificate = PkiCertificate
  { unPkiCertificate :: Text
  } deriving stock (Eq, Ord, Show)

instance FromJSON PkiCertificate where
  parseJSON = withObject "PkiCertificate" $ \o ->
    coerce @(_ Text) (o .: "certificate")

newtype CertificateSerial = CertificateSerial
  { unCertificateSerial :: Text }
  deriving stock (Eq, Ord, Show)
  deriving newtype (FromJSON, ToJSON, IsString)


-- | Returns the certificate in PEM formatting.
--
-- You can also use values @ca@, @crl@ or @ca_chain@ wrapped in
-- 'CertificateSerial'
readPkiCertificate
  :: CertificateSerial
  -> VaultRequest PkiCertificate
readPkiCertificate = readPkiCertificateAt "pki"

readPkiCertificateAt :: MountPoint -> CertificateSerial -> VaultRequest PkiCertificate
readPkiCertificateAt mp serial =
  mkVaultRequest_ methodGet
  ["v1", coerce mp, "cert", coerce serial]

-- | Returns a list of the current certificates by serial number only.
listPkiCertificates :: VaultRequest (KeyList CertificateSerial)
listPkiCertificates = listPkiCertificatesAt "pki"

listPkiCertificatesAt :: MountPoint -> VaultRequest (KeyList CertificateSerial)
listPkiCertificatesAt mp =
  mkVaultRequest_ methodList
  ["v1", unMountPoint mp, "certs"]

data PkiCrlConfiguration = PkiCrlConfiguration
  { expiry  :: !Text
    -- ^ Specifies the time until expiration.
  , disable :: !Bool
    -- ^ Disables or enables CRL building.
  } deriving stock (Eq, Show, Generic)

setPkiCrlConfigurationAt :: MountPoint -> PkiCrlConfiguration -> VaultWrite
setPkiCrlConfigurationAt mp =
  mkVaultWriteJSON methodPost
  [ "v1", unMountPoint mp, "config", "crl"]

-- | This endpoint allows setting the duration for which the generated CRL should be marked valid.
setPkiCrlConfiguration :: PkiCrlConfiguration -> VaultWrite
setPkiCrlConfiguration = setPkiCrlConfigurationAt "pki"

readPkiCrlConfigurationAt :: MountPoint -> VaultRequest PkiCrlConfiguration
readPkiCrlConfigurationAt mp =
  mkVaultRequest_ methodGet
  ["v1", unMountPoint mp, "config", "crl"]

-- | This endpoint allows getting the duration for which the generated CRL should be marked valid.
readPkiCrlConfiguration :: VaultRequest PkiCrlConfiguration
readPkiCrlConfiguration = readPkiCrlConfigurationAt "pki"

data PkiUrls = PkiUrls
  { issuing_certificates    :: ![Text]
  -- ^ Specifies the URL values for the Issuing Certificate field.
  , crl_distribution_points :: ![Text]
  -- ^ Specifies the URL values for the CRL Distribution Points field.
  , ocsp_servers            :: ![Text]
  -- ^ Specifies the URL values for the OCSP Servers field.
  } deriving stock (Eq, Show, Generic)

mkPkiUrls :: PkiUrls
mkPkiUrls = PkiUrls [] [] []

-- | This endpoint fetches the URLs to be encoded in generated certificates.
readPkiUrls :: VaultRequest PkiUrls
readPkiUrls = readPkiUrlsAt "pki"

readPkiUrlsAt :: MountPoint -> VaultRequest PkiUrls
readPkiUrlsAt mp =
  mkVaultRequest_ methodGet
  ["v1", unMountPoint mp, "config", "urls"]

-- | This endpoint allows setting the issuing certificate endpoints, CRL
-- distribution points, and OCSP server endpoints that will be encoded into
-- issued certificates.
setPkiUrls :: PkiUrls -> VaultWrite
setPkiUrls = setPkiUrlsAt "pki"

setPkiUrlsAt
  :: MountPoint
  -> PkiUrls
  -> VaultWrite
setPkiUrlsAt mp =
  mkVaultWriteJSON methodPost
  ["v1", unMountPoint mp, "config", "urls"]


newtype PkiRoleName = PkiRoleName { unPkiRoleName :: Text }
  deriving stock (Eq, Ord, Show)
  deriving newtype (IsString)

data PkiCertificateParams = PkiCertificateParams
  { common_name          :: !Text
    -- ^ Specifies the requested CN for the certificate. If the CN is allowed by role policy, it will be issued.
  , alt_names            :: !Text
    -- ^ Specifies requested Subject Alternative Names, in a comma-delimited
    -- list. These can be host names or email addresses; they will be parsed
    -- into their respective fields. If any requested names do not match role
    -- policy, the entire request will be denied.
  , ip_sans              :: !Text
    -- ^ Specifies requested IP Subject Alternative Names, in a comma-delimited
    -- list. Only valid if the role allows IP SANs (which is the default).
  , uri_sans             :: !Text
    -- ^ Specifies the requested URI Subject Alternative Names, in a
    -- comma-delimited list.
  , other_sans           :: !Text
    -- ^ Specifies custom OID/UTF8-string SANs. These must match values
    -- specified on the role in allowed_other_sans (see role creation for
    -- allowed_other_sans globbing rules). The format is the same as OpenSSL:
    -- @<oid>;<type>:<value>@ where the only current valid type is UTF8.
    -- This can be a comma-delimited list or a JSON string slice.
  , ttl                  :: !Int
    -- ^ Specifies requested Time To Live. Cannot be greater than the role's
    -- max_ttl value. If not provided, the role's ttl value will be used.
    -- Note that the role values default to system values if not explicitly set.
  , format               :: !Text
    -- ^ Specifies the format for returned data. Can be pem, der, or pem_bundle;
    -- defaults to pem. If der, the output is base64 encoded. If pem_bundle,
    -- the certificate field will contain the private key and certificate,
    -- concatenated; if the issuing CA is not a Vault-derived self-signed root,
    -- this will be included as well.

  , private_key_format   :: !Text
    -- ^ Specifies the format for marshaling the private key. Defaults to der
    -- which will return either base64-encoded DER or PEM-encoded DER, depending
    -- on the value of format. The other option is pkcs8 which will return the
    -- key marshalled as PEM-encoded PKCS8.
  , exclude_cn_from_sans :: !Bool
    -- ^ If true, the given common_name will not be included in DNS or Email
    -- Subject Alternate Names (as appropriate). Useful if the CN is not a
    -- hostname or email address, but is instead some human-readable identifier.
  }
  deriving stock (Eq, Show, Generic)

mkPkiCertificateParams
  :: Text -- ^ Common name
  -> PkiCertificateParams
mkPkiCertificateParams cn = PkiCertificateParams
  { common_name = cn
  , alt_names = mempty
  , ip_sans = mempty
  , uri_sans = mempty
  , other_sans = mempty
  , ttl = 0
  , format = "pem"
  , private_key_format = ""
  , exclude_cn_from_sans = False
  }

newtype PkiPrivateKey = PkiPrivateKey
  { unPkiPrivateKey :: Text }
  deriving stock (Eq)
  deriving newtype (FromJSON)

instance Show PkiPrivateKey where
  show _ = "PkiPrivatekey { unPkiPrivateKey = \"***SECRET***\" }"

data PkiIssuedCertificate = PkiIssuedCertificate
  { certificate      :: Text
  , issuing_ca       :: Text
  , ca_chain         :: Maybe [Text]
  , private_key      :: PkiPrivateKey
  , private_key_type :: Text
  , serial_number    :: CertificateSerial
  }
  deriving stock (Eq, Show, Generic)

-- | This endpoint generates a new set of credentials (private key and
-- certificate) based on the role named in the endpoint. The issuing CA
-- certificate is returned as well, so that only the root CA need be in a
-- client's trust store.
issuePkiCertificate
  :: PkiRoleName
  -> PkiCertificateParams
  -> VaultRequest PkiIssuedCertificate
issuePkiCertificate = issuePkiCertificateAt "pki"

issuePkiCertificateAt
  :: MountPoint
  -> PkiRoleName
  -> PkiCertificateParams
  -> VaultRequest PkiIssuedCertificate
issuePkiCertificateAt mp rn =
  mkVaultRequestJSON methodPost
  ["v1", unMountPoint mp, "issue", unPkiRoleName rn]

newtype PkiRevocationTime = PkiRevocationTime
  { unPkiRevocationTime :: Int }
  deriving stock (Eq, Ord, Show)

instance FromJSON PkiRevocationTime where
  parseJSON = withObject "PkiRevocationTime" $ \o ->
    coerce @(_ Int) $ o .: "revocation_time"

revokePkiCertificateAt
  :: MountPoint
  -> CertificateSerial
  -> VaultRequest PkiRevocationTime
revokePkiCertificateAt mp sn =
  mkVaultRequest methodPost
  ["v1", unMountPoint mp, "revoke"]
  (Just . encodingToLazyByteString . pairs $ "serial_number" .= sn)

-- | This endpoint revokes a certificate using its serial number. This is an
-- alternative option to the standard method of revoking using Vault lease IDs.
-- A successful revocation will rotate the CRL.
revokePkiCertificate :: CertificateSerial -> VaultRequest PkiRevocationTime
revokePkiCertificate = revokePkiCertificateAt "pki"


data PkiRole = PkiRole
  { ttl                                :: !Int
    -- ^ Specifies the Time To Live value provided as a string duration with
    -- time suffix. Hour is the largest suffix. If not set, uses the system
    -- default value or the value of max_ttl, whichever is shorter.
  , max_ttl                            :: !Int
    -- ^ Specifies the maximum Time To Live provided as a string duration with
    -- time suffix. Hour is the largest suffix. If not set, defaults to the
    -- system maximum lease TTL.
  , allow_localhost                    :: !Bool -- (bool: true)
    -- ^ Specifies if clients can request certificates for localhost as one of
    -- the requested common names. This is useful for testing and to allow
    -- clients on a single host to talk securely.
  , allowed_domains                    :: ![Text]
    -- ^ Specifies the domains of the role. This is used with the
    -- allow_bare_domains and allow_subdomains options.

  , allowed_domains_template           :: !Bool
    -- ^ When set, allowed_domains may contain templates, as with ACL Path
    -- Templating.
  , allow_bare_domains                 :: !Bool
    -- ^ Specifies if clients can request certificates matching the value of the
    -- actual domains themselves.

  , allow_subdomains                   :: !Bool
    -- ^ Specifies if clients can request certificates with CNs that are
    -- subdomains of the CNs allowed by the other role options. This includes
    -- wildcard subdomains.
  , allow_glob_domains                 :: !Bool
    -- ^ Allows names specified in allowed_domains to contain glob patterns.
  , allow_any_name                     :: !Bool
    -- ^ Specifies if clients can request any CN.
  , enforce_hostnames                  :: !Bool -- (bool: true)
    -- ^ Specifies if only valid host names are allowed for CNs, DNS SANs, and
    -- the host part of email addresses.

  , allow_ip_sans                      :: !Bool -- (bool: true)
    -- ^ Specifies if clients can request IP Subject Alternative Names.
  , allowed_uri_sans                   :: ![Text]
    -- ^ Defines allowed URI Subject Alternative Names.
  , allowed_other_sans                 :: ![Text]
    -- ^ Defines allowed custom OID/UTF8-string SANs.
    -- Same format as OpenSSL: @<oid>;<type>:<value>@
  , server_flag                        :: !Bool -- (bool: true)
    -- ^ Specifies if certificates are flagged for server use.

  , client_flag                        :: !Bool -- (bool: true)
    -- ^ Specifies if certificates are flagged for client use.

  , code_signing_flag                  :: !Bool -- (bool: false)
    -- ^ Specifies if certificates are flagged for code signing use.

  , email_protection_flag              :: !Bool -- (bool: false)
    -- ^ Specifies if certificates are flagged for email protection use.

  , key_type                           :: !Text --  (string: "rsa")
    -- ^ Specifies the type of key to generate for generated private keys and
    -- the type of key expected for submitted CSRs.

  , key_bits                           :: !Int -- (int: 2048)
    -- ^ Specifies the number of bits to use for the generated keys.
  , key_usage                          :: ![Text] -- (list: ["DigitalSignature", "KeyAgreement", "KeyEncipherment"])
    -- ^ Specifies the allowed key usage constraint on issued certificates.
  , ext_key_usage                      :: ![Text] -- (list: [])
    -- ^ Specifies the allowed extended key usage constraint on issued
    -- certificates.
  , ext_key_usage_oids                 :: ![Text]
    -- ^ A comma-separated string or list of extended key usage oids.
  , use_csr_common_name                :: !Bool -- (bool: true)
    -- ^ When used with the CSR signing endpoint, the common name in the CSR
    -- will be used instead of taken from the JSON data.
  , use_csr_sans                       :: !Bool --  (bool: true)
    -- ^ When used with the CSR signing endpoint, the subject alternate names in
    -- the CSR will be used instead of taken from the JSON data.

  , ou                                 :: ![Text]
    -- ^ Specifies the OU (OrganizationalUnit) values in the subject field of
    -- issued certificates.
  , organization                       :: ![Text]
    -- ^ Specifies the O (Organization) values in the subject field of issued
    -- certificates.

  , country                            :: ![Text] -- (string: "")
    -- ^ Specifies the C (Country) values in the subject field of issued
    -- certificates.
  , locality                           :: ![Text]
    -- ^ Specifies the L (Locality) values in the subject field of issued
    -- certificates.

  , province                           :: ![Text]
    -- ^ Specifies the ST (Province) values in the subject field of issued
    -- certificates.

  , street_address                     :: ![Text]
    -- ^ Specifies the Street Address values in the subject field of issued
    -- certificates.

  , postal_code                        :: ![Text]
    -- ^ Specifies the Postal Code values in the subject field of issued
    -- certificates.

--  , serial_number                      :: !(Maybe CertificateSerial)
--    -- ^ Specifies the Serial Number, if any. Otherwise Vault will generate a
--    -- random serial for you.

  , generate_lease                     :: !Bool -- (bool: false)
    -- ^ Specifies if certificates issued/signed against this role will have
    -- Vault leases attached to them. Certificates can be added to the CRL
    -- by vault revoke <lease_id> when certificates are associated with leases.

  , no_store                           :: !Bool -- (bool: false)
    -- ^ If set, certificates issued/signed against this role will not be stored
    -- in the storage backend.
  , require_cn                         :: !Bool -- (bool: true)
    -- ^ If set to false, makes the common_name field optional while generating
    -- a certificate.

  , policy_identifiers                 :: ![Text]
    -- ^ A list of policy OIDs.

  , basic_constraints_valid_for_non_ca :: !Bool -- (bool: false)
    -- ^ Mark Basic Constraints valid when issuing non-CA certificates.
  , not_before_duration                :: !Int -- (duration: "30s")
    -- ^ Specifies the duration by which to backdate the NotBefore property.
  }
  deriving stock (Eq, Show, Generic)

createPkiRoleAt
  :: MountPoint
  -> PkiRoleName
  -> PkiRole
  -> VaultWrite
createPkiRoleAt mp rn =
  mkVaultWriteJSON methodPost
  ["v1", unMountPoint mp, "roles", unPkiRoleName rn]

-- | This endpoint creates or updates the role definition.
createPkiRole :: PkiRoleName -> PkiRole -> VaultWrite
createPkiRole = createPkiRoleAt "pki"

mkPkiRole :: PkiRole
mkPkiRole = PkiRole
  { ttl = 0
  , max_ttl = 0
  , allow_localhost = True
  , allowed_domains = []
  , allowed_domains_template = False
  , allow_bare_domains = False
  , allow_subdomains = False
  , allow_glob_domains = False
  , allow_any_name = False
  , enforce_hostnames = True
  , allow_ip_sans = True
  , allowed_uri_sans = []
  , allowed_other_sans = []
  , server_flag = True
  , client_flag = True
  , code_signing_flag =False
  , email_protection_flag = False
  , key_type = "rsa"
  , key_bits = 2048
  , key_usage = ["DigitalSignature", "KeyAgreement", "KeyEncipherment"]
  , ext_key_usage = []
  , ext_key_usage_oids = []
  , use_csr_common_name = True
  , use_csr_sans = True ,
    ou = []
  , organization = []
  , country = []
  , locality = []
  , province = []
  , street_address = []
  , postal_code = []
--  , serial_number = Nothing
  , generate_lease = False
  , no_store = False
  , require_cn = True
  , policy_identifiers = []
  , basic_constraints_valid_for_non_ca = False
  , not_before_duration = 30
  }

readPkiRoleAt :: MountPoint -> PkiRoleName -> VaultRequest PkiRole
readPkiRoleAt mp rn =
  mkVaultRequest_ methodGet
  ["v1", unMountPoint mp, "roles", unPkiRoleName rn]

-- | This endpoint queries the role definition.
readPkiRole :: PkiRoleName -> VaultRequest PkiRole
readPkiRole = readPkiRoleAt "pki"

deletePkiRoleAt :: MountPoint -> PkiRoleName -> VaultWrite
deletePkiRoleAt mp rn =
  mkVaultWrite_ methodDelete
  ["v1", unMountPoint mp, "roles", unPkiRoleName rn]

-- | This endpoint deletes the role definition. Deleting a role does not revoke
-- certificates previously issued under this role.
deletePkiRole :: PkiRoleName -> VaultWrite
deletePkiRole = deletePkiRoleAt "pki"


--type (string: <required>) – Specifies the type of the root to create. If exported, the private key will be returned in the response; if internal the private key will not be returned and cannot be retrieved later. This is part of the request URL.

data PkiRootCertificateParams = PkiRootCertificateParams
  { common_name           :: !Text
    -- ^ Specifies the requested CN for the certificate.
  , alt_names             :: !Text
    -- ^ Specifies the requested Subject Alternative Names, in a comma-delimited
    -- list. These can be host names or email addresses; they will be parsed
    -- into their respective fields.
  , ip_sans               :: !Text
    -- ^ Specifies the requested IP Subject Alternative Names, in a
    -- comma-delimited list.
  , uri_sans              :: !Text
    -- ^ Specifies the requested URI Subject Alternative Names, in a
    -- comma-delimited list.
  , other_sans            :: ![Text]
    -- ^ Specifies custom OID/UTF8-string SANs. These must match values
    -- specified on the role in allowed_other_sans (see role creation for
    -- allowed_other_sans globbing rules). The format is the same as OpenSSL:
    -- @<oid>;<type>:<value>@ where the only current valid type is UTF8.
  , ttl                   :: !Int
    -- ^ Specifies the requested Time To Live (after which the certificate
    -- will be expired). This cannot be larger than the engine's max (or, if not
    -- set, the system max).
  , format                :: !Text
    -- ^ Specifies the format for returned data. Can be pem, der, or pem_bundle.
  , private_key_format    :: !Text
    -- ^ Specifies the format for marshaling the private key. Defaults to der
    -- which will return either base64-encoded DER or PEM-encoded DER, depending
    -- on the value of format. The other option is pkcs8 which will return the
    -- key marshalled as PEM-encoded PKCS8.

  , key_type              :: !Text
    -- ^ Specifies the desired key type; must be rsa, ed25519 or ec.
  , key_bits              :: !Int
    -- ^ Specifies the number of bits to use. This must be changed to a valid
    -- value if the key_type is ec, e.g., 224, 256, 384 or 521.

  , max_path_length       :: !Int
    -- ^ Specifies the maximum path length to encode in the generated
    -- certificate. -1 means no limit. A limit of 0 means a literal path length
    -- of zero.

  , exclude_cn_from_sans  :: !Bool
    -- ^ If set, the given common_name will not be included in DNS or Email
    -- Subject Alternate Names (as appropriate).
  , permitted_dns_domains :: ![Text]
    -- ^ A comma separated string (or, string array) containing DNS domains for
    -- which certificates are allowed to be issued or signed by this CA
    -- certificate.

  , ou                    :: ![Text]
    -- ^ Specifies the OU (OrganizationalUnit) values in the subject field of
    -- issued certificates.
  , organization          :: ![Text]
    -- ^ Specifies the O (Organization) values in the subject field of issued
    -- certificates.

  , country               :: ![Text] -- (string: "")
    -- ^ Specifies the C (Country) values in the subject field of issued
    -- certificates.
  , locality              :: ![Text]
    -- ^ Specifies the L (Locality) values in the subject field of issued
    -- certificates.

  , province              :: ![Text]
    -- ^ Specifies the ST (Province) values in the subject field of issued
    -- certificates.

  , street_address        :: ![Text]
    -- ^ Specifies the Street Address values in the subject field of issued
    -- certificates.

  , postal_code           :: ![Text]
    -- ^ Specifies the Postal Code values in the subject field of issued
    -- certificates.

  , serial_number         :: !(Maybe CertificateSerial)
    -- ^ Specifies the Serial Number, if any. Otherwise Vault will generate a
    -- random serial for you.
  } deriving stock (Show, Eq, Generic)


mkPkiRootCertificateParams
  :: Text -- ^ Common name
  -> PkiRootCertificateParams
mkPkiRootCertificateParams cn = PkiRootCertificateParams
  { common_name = cn
  , alt_names = mempty
  , ip_sans = mempty
  , uri_sans = mempty
  , other_sans = mempty
  , ttl = 0
  , format = "pem"
  , private_key_format = ""
  , key_type = "rsa"
  , key_bits = 2048
  , max_path_length = -1
  , exclude_cn_from_sans = False
  , permitted_dns_domains = mempty
  , ou = []
  , organization = []
  , country = []
  , locality = []
  , province = []
  , street_address = []
  , postal_code = []
  , serial_number = Nothing
  }


data PkiIssuedRootCertificate = PkiIssuedRootCertificate
  { certificate   :: Text
  , issuing_ca    :: Text
  , ca_chain      :: Maybe [Text]
  , serial_number :: CertificateSerial
  }
  deriving stock (Eq, Show, Generic)


generatePkiRootCertificateAt
  ::  MountPoint
  -> PkiRootCertificateParams
  -> VaultRequest PkiIssuedRootCertificate
generatePkiRootCertificateAt mp =
  mkVaultRequestJSON methodPost
  ["v1", unMountPoint mp, "root", "generate", "internal"]

-- | This endpoint generates a new self-signed CA certificate and private key.
generatePkiRootCertificate
  :: PkiRootCertificateParams
  -> VaultRequest PkiIssuedRootCertificate
generatePkiRootCertificate = generatePkiRootCertificateAt "pki"


generateExportedPkiRootCertificateAt
  :: MountPoint
  -> PkiRootCertificateParams
  -> VaultRequest PkiIssuedCertificate
generateExportedPkiRootCertificateAt mp =
  mkVaultRequestJSON methodPost
  ["v1", unMountPoint mp, "root", "generate", "exported"]

-- | This endpoint generates a new self-signed CA certificate and private key.
-- Unlike 'generateRootCertificate' this also returns private key.
generateExportedPkiRootCertificate
  :: PkiRootCertificateParams
  -> VaultRequest PkiIssuedCertificate
generateExportedPkiRootCertificate = generateExportedPkiRootCertificateAt "pki"

deletePkiRootCertificateAt :: MountPoint -> VaultWrite
deletePkiRootCertificateAt mp =
  mkVaultWrite_ methodDelete
  ["v1", unMountPoint mp, "root"]

-- | This endpoint deletes the current CA key (the old CA certificate will still
-- be accessible for reading until a new certificate/key is generated or
-- uploaded)
deletePkiRootCertificate :: VaultWrite
deletePkiRootCertificate = deletePkiRootCertificateAt "pki"



concat <$> sequence
  [ vaultDeriveToJSON ''PkiUrls
  , vaultDeriveFromJSON ''PkiUrls
  , vaultDeriveToJSON ''PkiCrlConfiguration
  , vaultDeriveFromJSON ''PkiCrlConfiguration
  , vaultDeriveToJSON ''PkiCertificateParams
  , vaultDeriveFromJSON ''PkiCertificateParams
  , vaultDeriveFromJSON ''PkiIssuedCertificate
  , vaultDeriveToJSON ''PkiRole
  , vaultDeriveFromJSON ''PkiRole
  , vaultDeriveToJSON ''PkiRootCertificateParams
  , vaultDeriveFromJSON ''PkiIssuedRootCertificate
  ]
