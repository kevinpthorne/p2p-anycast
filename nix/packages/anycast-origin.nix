{ lib, buildGoModule }:

buildGoModule {
  pname = "anycast-origin";
  version = "0.1.0";
  src = ../..;
  subPackages = [ "cmd/anycast-origin" ];
  vendorHash = null;

  meta = with lib; {
    description = "MeshCast origin sidecar daemon";
    homepage = "https://github.com/p2p-anycast/p2p-anycast";
    license = licenses.asl20;
    mainProgram = "anycast-origin";
  };
}
