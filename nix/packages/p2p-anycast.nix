{ lib, buildGoModule }:

buildGoModule {
  pname = "p2p-anycast";
  version = "0.1.0";
  src = ../..;
  subPackages = [ "cmd/anycast-edge" "cmd/anycast-origin" "cmd/anycast-ca" ];
  vendorHash = null;

  meta = with lib; {
    description = "MeshCast (p2p-anycast) complete binary suite";
    homepage = "https://github.com/p2p-anycast/p2p-anycast";
    license = licenses.asl20;
    mainProgram = "anycast-edge";
  };
}
