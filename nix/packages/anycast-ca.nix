{ lib, buildGoModule }:

buildGoModule {
  pname = "anycast-ca";
  version = "0.1.0";
  src = ../..;
  subPackages = [ "cmd/anycast-ca" ];
  vendorHash = null;

  meta = with lib; {
    description = "MeshCast post-quantum CA CLI tool";
    homepage = "https://github.com/p2p-anycast/p2p-anycast";
    license = licenses.asl20;
    mainProgram = "anycast-ca";
  };
}
