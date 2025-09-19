use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::Uri;
use shadowsocks::{
    config::{ServerConfig, ServerType},
    crypto::CipherKind,
    relay::Address,
    context::Context as SsContext,
    ProxyClientStream,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use url::Url;
use base64::prelude::{Engine as _, BASE64_STANDARD};

use crate::{
    connect::{BoxError, Conn},
    proxy::Intercepted,
};

#[cfg(feature = "default-tls")]
use native_tls_crate as native_tls;

pub struct UnpinProxyClientStream(pub Box<shadowsocks::ProxyClientStream<shadowsocks::net::TcpStream>>);

impl UnpinProxyClientStream {
    fn new(stream: shadowsocks::ProxyClientStream<shadowsocks::net::TcpStream>) -> Self {
        Self(Box::new(stream))
    }
}

impl AsyncRead for UnpinProxyClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for UnpinProxyClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

impl hyper::rt::Read for UnpinProxyClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let n = unsafe {
            let mut tbuf = ReadBuf::uninit(buf.as_mut());
            match Pin::new(&mut *self.0).poll_read(cx, &mut tbuf) {
                Poll::Ready(Ok(())) => tbuf.filled().len(),
                other => return other,
            }
        };

        unsafe {
            buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl hyper::rt::Write for UnpinProxyClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut *self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut *self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

impl hyper_util::client::legacy::connect::Connection for UnpinProxyClientStream {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

impl crate::connect::TlsInfoFactory for UnpinProxyClientStream {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        None
    }
}

#[cfg(feature = "default-tls")]
impl crate::connect::TlsInfoFactory for tokio_native_tls::TlsStream<hyper_util::rt::TokioIo<UnpinProxyClientStream>> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        let peer_certificate = self
            .get_ref()
            .peer_certificate()
            .ok()
            .flatten()
            .and_then(|c| c.to_der().ok());
        Some(crate::tls::TlsInfo { peer_certificate })
    }
}

#[cfg(feature = "default-tls")]
impl hyper_util::client::legacy::connect::Connection for crate::connect::native_tls_conn::NativeTlsConn<hyper_util::rt::TokioIo<UnpinProxyClientStream>> {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

pub(super) async fn connect_ss(
    connector: super::ConnectorService,
    dst: Uri,
    proxy: Intercepted,
) -> Result<Conn, BoxError> {

    
    // 检查是否有原始的 Shadowsocks URL
    let proxy_url = if let Some(ss) = proxy.ss() {
        ss.clone()
    } else {
        Url::parse(&proxy.uri().to_string())?
    };
    let (cipher, password) = parse_proxy_auth(&proxy_url)?;

    let server_addr = proxy_url.socket_addrs(|| None)?[0];
    let sc = ServerConfig::new(
        server_addr,
        &password,
        cipher,
    )?;

    let host = dst.host().ok_or("no host in url")?.to_string();
    let port = dst
        .port_u16()
        .unwrap_or_else(|| if dst.scheme() == Some(&http::uri::Scheme::HTTPS) {
            443
        } else {
            80
        });
    let target_addr = Address::from((host.clone(), port));

    let ctx = Arc::new(SsContext::new(ServerType::Local));
    let stream = ProxyClientStream::connect(ctx, &sc, &target_addr).await?;
    let stream = UnpinProxyClientStream::new(stream);
    let io = hyper_util::rt::TokioIo::new(stream);

    if dst.scheme() == Some(&http::uri::Scheme::HTTPS) {
        match &connector.inner {
            #[cfg(feature = "default-tls")]
            super::Inner::DefaultTls(_, _) => {
                let mut builder = native_tls::TlsConnector::builder();
                builder.danger_accept_invalid_certs(true);

                let tls_connector = tokio_native_tls::TlsConnector::from(
                    builder.build().map_err(|e| Box::new(e) as BoxError)?,
                );

                let stream = match tls_connector.connect(&host, io).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        log::error!("TLS connection failed: {}", e);
                        return Err(Box::new(e));
                    }
                };
                let conn = super::sealed::Conn {
                    inner: connector.verbose.wrap(super::native_tls_conn::NativeTlsConn { inner: hyper_util::rt::TokioIo::new(stream) }),
                    is_proxy: false,
                    tls_info: connector.tls_info,
                };
                return Ok(conn);
            }            #[cfg(feature = "__rustls")]
            super::Inner::RustlsTls { tls, .. } => {
                use std::convert::TryFrom;
                use tokio_rustls::TlsConnector as RustlsConnector;
                let server_name = rustls_pki_types::ServerName::try_from(host.as_str())
                    .map_err(|e| Box::new(e) as BoxError)?
                    .to_owned();
                let stream = match RustlsConnector::from(tls.clone()).connect(server_name, io).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        log::error!("TLS connection failed: {}", e);
                        return Err(Box::new(e));
                    }
                };
                let conn = super::sealed::Conn {
                    inner: connector.verbose.wrap(super::rustls_tls_conn::RustlsTlsConn { inner: hyper_util::rt::TokioIo::new(stream) }),
                    is_proxy: false,
                    tls_info: connector.tls_info,
                };
                return Ok(conn);
            }
        }
    }

    let conn = super::sealed::Conn {
        inner: connector.verbose.wrap(io),
        is_proxy: false,
        tls_info: false,
    };
    Ok(conn)
}

fn parse_proxy_auth(proxy: &Url) -> Result<(CipherKind, String), BoxError> {
    let user = proxy.username();
    if user.is_empty() {
        return Err("proxy auth username is empty".into());
    }

    let mut b64 = user.to_string();
    while b64.len() % 4 != 0 {
        b64.push('=');
    }

    // The username in ss:// URLs is the base64 encoded string of "cipher:password".
    let decoded = BASE64_STANDARD.decode(b64.as_bytes())
        .map_err(|e| format!("proxy auth username is not valid base64: {}", e))?;
    let decoded_str = String::from_utf8(decoded)
        .map_err(|e| format!("decoded proxy auth is not valid utf-8: {}", e))?;

    let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(format!("invalid decoded proxy auth format, expected 'cipher:password', got: {}", decoded_str).into());
    }

    let cipher: CipherKind = parts[0]
        .parse()
        .map_err(|e| format!("invalid cipher '{}': {}", parts[0], e))?;
    let password = parts[1].to_string();

    Ok((cipher, password))
}

#[cfg(all(feature = "__rustls", not(target_arch = "wasm32")))]
impl crate::connect::TlsInfoFactory for tokio_rustls::client::TlsStream<hyper_util::rt::TokioIo<UnpinProxyClientStream>> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        let (_, session) = self.get_ref();
        let peer_certificate = session
            .peer_certificates()
            .and_then(|certs| certs.first().map(|c| c.to_vec()));
        Some(crate::tls::TlsInfo { peer_certificate })
    }
}

#[cfg(all(feature = "__rustls", not(target_arch = "wasm32")))]
impl hyper_util::client::legacy::connect::Connection for crate::connect::rustls_tls_conn::RustlsTlsConn<hyper_util::rt::TokioIo<UnpinProxyClientStream>> {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        if self.inner.inner().get_ref().1.alpn_protocol() == Some(b"h2") {
            self.inner
                .inner()
                .get_ref()
                .0
                .inner()
                .connected()
                .negotiated_h2()
        } else {
            self.inner.inner().get_ref().0.inner().connected()
        }
    }
}