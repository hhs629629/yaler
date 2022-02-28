use std::pin::Pin;
use std::sync::{Arc, Mutex};

use http::header::*;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use hyper::{body::HttpBody, client, Body};

use tokio::io::{split, AsyncReadExt, ReadHalf, WriteHalf};
use tokio::{
    io::{AsyncWriteExt, BufStream},
    net::{TcpListener, TcpStream, ToSocketAddrs},
};

use rustls::client::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use pext::FromUtf8;
use pext::IntoUtf8;

use tracing::{error, info, instrument, warn};

use crate::acceptor::AcceptorMap;
use crate::error::Error;
use crate::http::ReadHttpExt;

pub struct Server {
    listener: TcpListener,
    acceptors: Arc<Mutex<AcceptorMap>>,
    tls_connector: Arc<TlsConnector>,
}

impl Server {
    #[instrument(skip(acceptors))]
    pub async fn bind<A>(
        addr: A,
        root_store: RootCertStore,
        acceptors: Arc<Mutex<AcceptorMap>>,
    ) -> Result<Self, Error>
    where
        A: ToSocketAddrs + std::fmt::Debug,
    {
        Ok(Self {
            listener: TcpListener::bind(addr)
                .await
                .map_err(|e| Error::TcpBindError(e))?,
            acceptors,
            tls_connector: Arc::new(TlsConnector::from(Arc::new(
                ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(root_store)
                    .with_no_client_auth(),
            ))),
        })
    }

    #[instrument(skip(self))]
    pub async fn run(&self) -> Result<(), Error> {
        loop {
            let (stream, _addr) = self
                .listener
                .accept()
                .await
                .map_err(|e| Error::TcpAcceptError(e))?;

            let acceptors = self.acceptors.clone();
            let connector = self.tls_connector.clone();

            tokio::spawn(Self::handle_stream(stream, acceptors, connector));
        }
    }

    async fn handle_stream(
        stream: TcpStream,
        acceptors: Arc<Mutex<AcceptorMap>>,
        connector: Arc<TlsConnector>,
    ) {
        let mut stream = BufStream::new(stream);

        let mut buf = Vec::new();
        stream.read_until_header_end(&mut buf).await.unwrap();

        let req = Request::from_utf8(&buf).unwrap();

        info!(?req);

        if req.method() == Method::CONNECT {
            let host = req.uri().host().unwrap().to_string();
            let acceptor = {
                let mut map = acceptors.lock().unwrap();

                map.get(host.clone())
            };

            let remote = Self::connect_to_remote(&req, &mut stream).await.unwrap();

            match Self::handle_https(host.clone(), connector, acceptor, remote, stream.into_inner()).await {
                Ok(_) => return,
                Err(e) => error!(?host, ?e),
            }
        } else {
            Self::handle_http(req, stream).await;
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

        stream
            .write_all(&response.into_utf8().unwrap())
            .await
            .unwrap();
        stream.flush().await.unwrap();

        connection.map_err(Error::TcpConnectError)
    }

    #[instrument(skip(connector, acceptor))]
    async fn handle_https(
        host: String,
        connector: Arc<TlsConnector>,
        acceptor: Arc<TlsAcceptor>,
        remote: TcpStream,
        stream: TcpStream,
    ) -> Result<(), Error> {
        let remote = connector
            .connect(ServerName::try_from(host.as_str()).unwrap(), remote)
            .await
            .map_err(Error::TlsConnectError)?;
        let remote = TlsStream::Client(remote);

        let stream = acceptor
            .accept(stream)
            .await
            .map_err(Error::TlsAcceptError)?;
        let stream = TlsStream::Server(stream);

        let (remote_read, remote_write) = split(remote);
        let (stream_read, stream_write) = split(stream);

        let c_to_s = tokio::spawn(Self::link(stream_read, remote_write));
        Self::link(remote_read, stream_write).await?;
        c_to_s.await.unwrap()?;

        Ok(())
    }

    #[instrument]
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
        stream.flush().await.unwrap();

        while !body.is_end_stream() {
            let mut pin_body = Pin::new(&mut body);

            if let Some(Ok(buf)) = pin_body.data().await {
                let buf: Vec<_> = buf.to_vec();
                stream.write_all(&buf).await.unwrap();
                stream.flush().await.unwrap();
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

    #[instrument]
    async fn link(
        mut from: ReadHalf<TlsStream<TcpStream>>,
        mut to: WriteHalf<TlsStream<TcpStream>>,
    ) -> Result<(), Error> {
        loop {
            let mut buf = [0u8; 1024 * 10];

            let len = from.read(&mut buf).await.map_err(Error::ReadStreamError)?;

            if len == 0 {
                return Ok(());
            }

            to.write_all(&buf[..len])
                .await
                .map_err(Error::WriteStreamError)?;
            to.flush().await.map_err(Error::WriteStreamError)?;
        }
    }
}
