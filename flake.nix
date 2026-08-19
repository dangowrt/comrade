{
  description = "comrade: serverless peer-to-peer terminal sharing over a punched p2p link";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      # Linux only: the libdht derivation below builds a Linux shared object,
      # and macOS is served by the Homebrew tap (packaging/homebrew).
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (s: f nixpkgs.legacyPackages.${s});
    in {
      packages = forAll (pkgs:
        let
          # libjuice, kcp and jech/dht are not in nixpkgs; comrade links the
          # rest (libssh, openssl) from the distribution, staying an ordinary
          # consumer of shared libraries. These three derivations fill the gap
          # the same way the Debian and OpenWrt recipes do.
          libjuice = pkgs.stdenv.mkDerivation {
            pname = "libjuice";
            version = "1.7.3";
            src = pkgs.fetchFromGitHub {
              owner = "paullouisageneau";
              repo = "libjuice";
              rev = "v1.7.3";
              hash = "sha256-XUcutgrP96hdXGUl4JjN2iovdkwYRw9LP6ze6S4Wp+A=";
            };
            nativeBuildInputs = [ pkgs.cmake pkgs.ninja ];
            cmakeFlags = [ "-DNO_TESTS=ON" "-DUSE_NETTLE=OFF" ];
          };

          kcp = pkgs.stdenv.mkDerivation {
            pname = "kcp";
            version = "2.1.1";
            src = pkgs.fetchFromGitHub {
              owner = "skywind3000";
              repo = "kcp";
              rev = "2.1.1";
              hash = "sha256-K0kPQ2YjwwHkbGelo3KNcl+PpDnbk/FxDxYMu+VDARM=";
            };
            nativeBuildInputs = [ pkgs.cmake pkgs.ninja ];
            # Upstream sets no SOVERSION and pins cmake 4.0 for nothing used
            # here; impose an ABI epoch and relax the floor.
            postPatch = ''
              substituteInPlace CMakeLists.txt \
                --replace-warn "cmake_minimum_required(VERSION 4.0)" \
                               "cmake_minimum_required(VERSION 3.20)"
              echo 'set_target_properties(kcp PROPERTIES VERSION 2.1.1 SOVERSION 0)' >> CMakeLists.txt
            '';
            cmakeFlags = [ "-DBUILD_SHARED_LIBS=ON" "-DBUILD_TESTING=OFF" ];
          };

          libdht = pkgs.stdenv.mkDerivation {
            pname = "libdht";
            version = "2023.03.18";
            src = pkgs.fetchFromGitHub {
              owner = "jech";
              repo = "dht";
              rev = "0bbb8f4a5bd914b60de5e9fbb51573aa33a1cf18";
              hash = "sha256-1AY1lBYXCdSWR+4kPVe4IwZv8W53QWYkN6xeIsS20/A=";
            };
            # jech/dht ships a Makefile that builds a test binary, not a
            # library, so build the shared object directly. dht.c leaves four
            # symbols for the application to supply; -shared allows that.
            buildPhase = ''
              runHook preBuild
              $CC $NIX_CFLAGS_COMPILE -fPIC -Wall -c -o dht.o dht.c
              $CC -shared -Wl,-soname,libdht.so.0 -o libdht.so.0 dht.o
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              install -Dm755 libdht.so.0 $out/lib/libdht.so.0
              ln -s libdht.so.0 $out/lib/libdht.so
              install -Dm644 dht.h $out/include/dht/dht.h
              runHook postInstall
            '';
          };
        in rec {
          inherit libjuice kcp libdht;

          comrade = pkgs.stdenv.mkDerivation {
            pname = "comrade";
            # Version and build date from the commit, not pinned: the short rev
            # names the version, and lastModified (the commit's own timestamp)
            # becomes SOURCE_DATE_EPOCH so a given commit builds reproducibly.
            version = "0.1.0+git${self.shortRev or "dirty"}";
            src = self;
            SOURCE_DATE_EPOCH = toString (self.lastModified or 0);
            nativeBuildInputs = [ pkgs.cmake pkgs.ninja pkgs.pkg-config ];
            buildInputs = [ pkgs.libssh pkgs.openssl libjuice kcp libdht ];
            # No -DCOMRADE_DHT_DIR: find and link the packaged shared libdht,
            # exactly as the Arch and OpenWrt recipes do. Crypto follows
            # libssh, which nixpkgs builds against OpenSSL.
            cmakeFlags = [ "-DBUILD_TESTING=OFF" "-DCOMRADE_CRYPTO=auto" ];
            meta = with pkgs.lib; {
              description = "Serverless peer-to-peer terminal sharing with tmate-like semantics";
              homepage = "https://github.com/dangowrt/comrade";
              license = licenses.agpl3Plus;
              mainProgram = "comrade";
              platforms = platforms.unix;
            };
          };

          default = comrade;
        });

      apps = forAll (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.system}.comrade}/bin/comrade";
        };
      });
    };
}
