# Mode B spike (ADR-0008): FreeRDP proxy server. Packaging varies by distro release, so this tries the
# distro package first and fails loudly; if it is unavailable, build FreeRDP from source with -DWITH_PROXY=ON.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates freerdp3-proxy \
 && rm -rf /var/lib/apt/lists/* \
 && command -v freerdp-proxy3 >/dev/null || command -v freerdp-proxy >/dev/null
EXPOSE 3389
# Binary name differs by package version; the shell picks whichever exists.
CMD ["sh", "-c", "exec $(command -v freerdp-proxy3 || command -v freerdp-proxy) /etc/freerdp-proxy/config.ini"]
