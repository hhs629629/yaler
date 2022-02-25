use std::pin::Pin;
use std::sync::Arc;

use http::header::*;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use hyper::{body::HttpBody, client, Body};

use tokio::io::AsyncReadExt;
use tokio::{
    io::{AsyncWriteExt, BufStream},
    net::{TcpListener, TcpStream, ToSocketAddrs},
};

use rustls::client::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use pext::FromUtf8;
use pext::IntoUtf8;

use tracing::{info, instrument};

use crate::acceptor::Acceptor;
use crate::error::Error;
use crate::http::ReadHttpExt;

pub struct Server {
    listener: TcpListener,
    acceptor: Acceptor,
    tls_connector: TlsConnector,
}

impl Server {
    #[instrument(skip(acceptor))]
    pub async fn bind<A>(
        addr: A,
        root_store: RootCertStore,
        acceptor: Acceptor,
    ) -> Result<Self, Error>
    where
        A: ToSocketAddrs + std::fmt::Debug,
    {
        Ok(Self {
            listener: TcpListener::bind(addr)
                .await
                .map_err(|e| Error::TcpBindError(e))?,
            acceptor,
            tls_connector: TlsConnector::from(Arc::new(
                ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(root_store)
                    .with_no_client_auth(),
            )),
        })
    }

    #[instrument(skip(self))]
    pub async fn run(&mut self) -> Result<(), Error> {
        loop {
            let (stream, _addr) = self
                .listener
                .accept()
                .await
                .map_err(|e| Error::TcpAcceptError(e))?;

            let mut stream = BufStream::new(stream);
            let mut buf = Vec::new();

            stream.read_until_header_end(&mut buf).await?;
            let req = Request::from_utf8(&buf)?;

            info!("{:?}", req);

            if req.method() == Method::CONNECT {
                let remote = Self::connect_to_remote(&req, &mut stream).await.unwrap();
                let remote = self
                    .tls_connector
                    .connect(
                        ServerName::try_from(req.uri().host().unwrap()).unwrap(),
                        remote,
                    )
                    .await
                    .unwrap();

                let stream = match self
                    .acceptor
                    .get(req.uri().host().unwrap().to_string())
                    .accept(stream.into_inner())
                    .await
                {
                    Ok(stream) => stream,
                    Err(_) => continue,
                };

                tokio::spawn(async move {
                    Self::handle_https(req, remote, stream).await;
                });
            } else {
                tokio::spawn(async move {
                    Self::handle_http(req, stream).await;
                });
            }
        }
    }

    async fn connect_to_remote(
        req: &Request<Vec<u8>>,
        stream: &mut BufStream<TcpStream>,
    ) -> Result<TcpStream, Error> {
        let connection = TcpStream::connect(format!(
            "{}:{}",
            req.uri().host().unwrap(),
            req.uri().port().unwrap()
        ))
        .await;

        let status_code = if let Ok(_) = &connection {
            StatusCode::OK
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };

        let response = Response::builder()
            .version(req.version())
            .status(status_code)
            .body(Vec::new())
            .unwrap();

        stream.write_all(&response.into_utf8().unwrap()).await;
        stream.flush().await;

        connection.map_err(Error::TcpConnectError)
    }

    async fn handle_https(
        req: Request<Vec<u8>>,
        mut remote: tokio_rustls::client::TlsStream<TcpStream>,
        mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    ) {
        loop {
            let mut buf = [0u8; 1024];
            let len = stream.read(&mut buf).await.unwrap();
            print!("{}", String::from_utf8(buf[..len].to_vec()).unwrap());
        }
    }

    async fn handle_http(req: Request<Vec<u8>>, mut stream: BufStream<TcpStream>) {
        let client = client::Client::new();
        let (parts, empty) = req.into_parts();

        let body = if parts.method == &Method::POST {
            Self::read_body(&parts.headers, &mut stream).await
        } else {
            empty
        };
        let req = Request::from_parts(parts, Body::from(body));

        let response = client.request(req).await.unwrap();
        let (parts, mut body) = response.into_parts();
        let response = Response::from_parts(parts, Vec::new());

        stream
            .write_all(&response.into_utf8().unwrap())
            .await
            .unwrap();
        stream.flush().await;

        while !body.is_end_stream() {
            let mut pin_body = Pin::new(&mut body);

            if let Some(Ok(buf)) = pin_body.data().await {
                let buf: Vec<_> = buf.to_vec();
                stream.write_all(&buf).await;
                stream.flush().await;
            }
        }
    }

    async fn read_body(headers: &HeaderMap, stream: &mut BufStream<TcpStream>) -> Vec<u8> {
        let content_length = headers.get(CONTENT_LENGTH).unwrap();
        let content_length: usize = content_length.to_str().unwrap().parse().unwrap();

        let mut buf = Vec::with_capacity(content_length);
        stream.read_exact(&mut buf[..content_length]).await.unwrap();
        buf
    }
}
