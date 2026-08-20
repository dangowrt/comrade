# Intermediate builder image for the deb pipeline: a debian:<suite> with the apt
# toolchain and comrade's three dependency libraries (libjuice, kcp, jech/dht)
# already built and installed, so packaging/deb/build.sh only has to compile
# comrade and assemble the .debs. Built per suite and architecture and cached in
# the local registry (see .github/workflows/release.yml), so the slow per-arch
# dependency compiles happen only when a pinned version or prereqs.sh changes,
# not on every package build.
#
#   docker buildx build -f packaging/deb/Dockerfile --build-arg SUITE=stable .
#
# The build context is the repository root.
ARG SUITE=stable
FROM debian:${SUITE}

# Layout preserved so prereqs.sh finds ../versions.sh; both are removed after the
# build, leaving only the installed toolchain, libraries and the sentinel.
COPY packaging/versions.sh /build/packaging/versions.sh
COPY packaging/deb/prereqs.sh /build/packaging/deb/prereqs.sh
RUN sh /build/packaging/deb/prereqs.sh \
	&& rm -rf /build /var/lib/apt/lists/*
