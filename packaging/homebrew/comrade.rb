class Comrade < Formula
  desc "Serverless peer-to-peer terminal sharing over a punched p2p link"
  homepage "https://github.com/dangowrt/comrade"
  # The release CI stamps a stable `url` (the tagged commit) and a bottle block
  # into this formula when it pushes the tap, so `brew install comrade` fetches a
  # prebuilt bottle; libjuice, kcp and libdht get the same treatment, so the
  # whole dependency chain installs as binaries with no build toolchain needed.
  # `head` stays for `brew install --HEAD comrade`, which builds the current tip
  # of main; the build date is taken from the checked-out commit
  # (SOURCE_DATE_EPOCH, honoured by the CMake build) so the result is reproducible.
  head "https://github.com/dangowrt/comrade.git", branch: "main"
  license "AGPL-3.0-or-later"

  depends_on "cmake" => :build
  depends_on "ninja" => :build
  depends_on "pkgconf" => :build
  on_arm do
    depends_on "dangowrt/comrade/libjuice"
    depends_on "dangowrt/comrade/kcp"
    depends_on "dangowrt/comrade/libdht"
    depends_on "libssh"
    # OpenSSL is libssh's to choose, so it is declared as whatever libssh
    # links: a version named here is one libssh can move off, and comrade
    # would be left compiled against headers its runtime disagrees with.
    libssh_ssl = Formula["libssh"].deps.map(&:name).grep(/openssl/).first
    depends_on libssh_ssl if libssh_ssl
  end

  on_intel do
    # Homebrew ships no Intel bottle for libssh or the OpenSSL it wants, so
    # this arch carries its own: libssh on mbedTLS, both static, and comrade's
    # crypto then resolves to monocypher, whose wire output is identical to
    # OpenSSL's. Nothing here is linked by the other formulae.
    resource "mbedtls" do
      url "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2"
      sha256 "a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6"
    end

    resource "libssh" do
      url "https://www.libssh.org/files/0.12/libssh-0.12.2.tar.xz"
      sha256 "49560f677d96e3706a904ac2de1116e25f3680937d51e5c92198fcba4a1c1e9f"
    end

    resource "monocypher" do
      url "https://monocypher.org/download/monocypher-4.0.2.tar.gz"
      sha256 "38d07179738c0c90677dba3ceb7a7b8496bcfea758ba1a53e803fed30ae0879c"
    end

    resource "libjuice" do
      url "https://github.com/paullouisageneau/libjuice/archive/refs/tags/v1.7.3.tar.gz"
      sha256 "86e075ca4732882746b6d5733ff1b6090f942e5750df58630b191b5f00f30010"
    end

    resource "kcp" do
      url "https://github.com/skywind3000/kcp/archive/refs/tags/2.1.1.tar.gz"
      sha256 "54d3c80928d206529f67cba6f96f2c98007182b46e3112819b200d914f96e425"
    end

    resource "dht" do
      url "https://github.com/jech/dht/archive/0bbb8f4a5bd914b60de5e9fbb51573aa33a1cf18.tar.gz"
      sha256 "5f126d158979d14bcc17ed0debf4d875d662e8fc3fb3e71b29a8835e4044fdeb"
    end
  end

  # Every dependency, static, into a prefix of its own: libssh on mbedTLS,
  # monocypher for comrade's side, libjuice and kcp as archives. Returns the
  # prefix for CMAKE_PREFIX_PATH.
  def build_static_deps(pre)
    common = %W[
      -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=#{pre}
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_SHARED_LIBS=OFF
      -DCMAKE_OSX_DEPLOYMENT_TARGET=#{MacOS.version}
    ]
    resource("mbedtls").stage do
      # libssh's mbedTLS shim needs the threading layer.
      inreplace "include/mbedtls/mbedtls_config.h",
                "//#define MBEDTLS_THREADING_C", "#define MBEDTLS_THREADING_C"
      inreplace "include/mbedtls/mbedtls_config.h",
                "//#define MBEDTLS_THREADING_PTHREAD",
                "#define MBEDTLS_THREADING_PTHREAD"
      system "cmake", "-S", ".", "-B", "b", *common,
             "-DENABLE_TESTING=OFF", "-DENABLE_PROGRAMS=OFF",
             "-DUSE_STATIC_MBEDTLS_LIBRARY=ON",
             "-DUSE_SHARED_MBEDTLS_LIBRARY=OFF",
             "-DMBEDTLS_FATAL_WARNINGS=OFF"
      system "cmake", "--build", "b"
      system "cmake", "--install", "b"
    end
    resource("libssh").stage do
      system "cmake", "-S", ".", "-B", "b", *common,
             "-DCMAKE_PREFIX_PATH=#{pre}",
             "-DWITH_MBEDTLS=ON", "-DWITH_SERVER=ON", "-DWITH_SFTP=OFF",
             "-DWITH_ZLIB=OFF", "-DWITH_GSSAPI=OFF", "-DWITH_EXAMPLES=OFF",
             "-DUNIT_TESTING=OFF", "-DCLIENT_TESTING=OFF"
      system "cmake", "--build", "b"
      system "cmake", "--install", "b"
    end
    resource("monocypher").stage do
      # No CMake upstream, so the two objects are compiled by hand.
      system ENV.cc, "-std=c99", "-O2", "-c", "src/monocypher.c",
             "-o", "monocypher.o"
      system ENV.cc, "-std=c99", "-O2", "-Isrc", "-c",
             "src/optional/monocypher-ed25519.c", "-o", "monocypher-ed25519.o"
      system "ar", "rcs", "libmonocypher.a", "monocypher.o",
             "monocypher-ed25519.o"
      (pre/"lib").install "libmonocypher.a"
      (pre/"include").install "src/monocypher.h"
      (pre/"include").install "src/optional/monocypher-ed25519.h"
    end
    resource("libjuice").stage do
      system "cmake", "-S", ".", "-B", "b", *common
      system "cmake", "--build", "b"
      system "cmake", "--install", "b"
    end
    resource("kcp").stage do
      # kcp pins a cmake floor nothing used here needs.
      inreplace "CMakeLists.txt", /cmake_minimum_required\(VERSION[^)]*\)/i,
                "cmake_minimum_required(VERSION 3.20)"
      system "cmake", "-S", ".", "-B", "b", *common
      system "cmake", "--build", "b"
      system "cmake", "--install", "b"
    end
    pre
  end

  def install
    # Reproducible build date from the commit being built, not the clock. Both
    # the tagged (git url + revision) and --HEAD sources are git checkouts with a
    # .git to read, so this applies to a release build too.
    if File.directory?(".git")
      epoch = Utils.safe_popen_read("git", "log", "-1", "--format=%ct").strip
      ENV["SOURCE_DATE_EPOCH"] = epoch unless epoch.empty?
    end

    extra = []
    if Hardware::CPU.arm?
      ssl = Formula["libssh"].deps.map(&:name).grep(/openssl/).first
      odie "libssh links no OpenSSL; comrade's backend would not match" if ssl.nil?
      prefixes = %W[libjuice kcp libdht #{ssl} libssh]
                   .map { |f| Formula[f].opt_prefix }
      # libdht leaves four symbols for the application, so the binary is
      # linked with -export_dynamic to let the dylib resolve them back.
      extra << "-DCMAKE_EXE_LINKER_FLAGS=-Wl,-export_dynamic"
    else
      prefixes = [build_static_deps(buildpath/"static")]
      # jech/dht ships no library build, so it is compiled in from source and
      # there is no dylib left to resolve anything back to.
      resource("dht").stage { (buildpath/"dht").install Dir["*"] }
      extra << "-DCOMRADE_DHT_DIR=#{buildpath}/dht"
    end
    # A static libssh records no linkage, so the backend is named rather than
    # probed: mbedTLS has neither BLAKE2b nor Ed25519, and monocypher is what
    # the Windows static build pairs with it for the same reason.
    crypto = Hardware::CPU.arm? ? "auto" : "monocypher"
    system "cmake", "-S", ".", "-B", "build", "-G", "Ninja", *std_cmake_args,
           "-DCMAKE_BUILD_TYPE=Release",
           "-DCMAKE_PREFIX_PATH=#{prefixes.join(";")}",
           "-DCOMRADE_CRYPTO=#{crypto}",
           "-DBUILD_TESTING=OFF", *extra
    system "cmake", "--build", "build"
    system "cmake", "--install", "build"
  end

  def caveats
    <<~EOS
      Hosting a session needs tmux (joining one does not):
        brew install tmux
    EOS
  end

  test do
    # comrade prints its usage banner on stderr.
    assert_match "start a shared session", shell_output("#{bin}/comrade --help 2>&1")
    assert_match "no running session", shell_output("#{bin}/comrade show 2>&1", 1)
  end
end
