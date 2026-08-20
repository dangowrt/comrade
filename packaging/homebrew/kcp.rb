class Kcp < Formula
  desc "Fast and reliable ARQ protocol over UDP"
  homepage "https://github.com/skywind3000/kcp"
  url "https://github.com/skywind3000/kcp/archive/refs/tags/2.1.1.tar.gz"
  sha256 "54d3c80928d206529f67cba6f96f2c98007182b46e3112819b200d914f96e425"
  license "MIT"

  depends_on "cmake" => :build
  depends_on "ninja" => :build

  # Upstream honours BUILD_SHARED_LIBS but sets no VERSION/SOVERSION, so a bare
  # libkcp.dylib is installed. The dylib carries its own install_name, so
  # consumers resolve it regardless; 0 is treated as the packaged ABI epoch.
  def install
    system "cmake", "-S", ".", "-B", "build", "-G", "Ninja", *std_cmake_args,
           "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=ON"
    system "cmake", "--build", "build"
    system "cmake", "--install", "build"
  end

  test do
    (testpath/"t.c").write <<~C
      #include <ikcp.h>
      int main(void) { ikcpcb *k = ikcp_create(1, 0); ikcp_release(k); return 0; }
    C
    system ENV.cc, "t.c", "-I#{include}", "-L#{lib}", "-lkcp", "-o", "t"
    system "./t"
  end
end
