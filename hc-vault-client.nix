{ mkDerivation, aeson, base, bytestring, containers, http-client
, http-client-tls, http-types, lib, template-haskell, text, time
, transformers, unliftio, uuid-types
}:
mkDerivation {
  pname = "hc-vault-client";
  version = "0.1.0";
  src = ./.;
  libraryHaskellDepends = [
    aeson base bytestring containers http-client http-client-tls
    http-types template-haskell text time transformers unliftio
    uuid-types
  ];
  testHaskellDepends = [
    aeson base containers http-client http-client-tls http-types text
    time transformers unliftio
  ];
  description = "Client for HashiCorp Vault";
  license = lib.licenses.asl20;
}
