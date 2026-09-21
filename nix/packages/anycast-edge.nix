{ lib, buildGoModule }:

buildGoModule {
  pname = "anycast-edge";
  version = "0.1.0";
  src = ../..;
  subPackages = [ "cmd/anycast-edge" ];
  vendorHash = null;

  meta = with lib; {
    description = "MeshCast decentralized edge router daemon";
    homepage = "https://github.com/p2p-anycast/p2p-anycast";
    license = licenses.asl20;
    mainProgram = "anycast-edge";
  };
}
