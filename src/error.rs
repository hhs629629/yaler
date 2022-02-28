use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Fail to bind tcp listener")]
    TcpBindError(std::io::Error),

    #[error("Fail to accept client with tcp")]
    TcpAcceptError(std::io::Error),

    #[error("Fail to connect remote with tcp")]
    TcpConnectError(std::io::Error),

    #[error("Fail to accept client with tls")]
    TlsAcceptError(std::io::Error),

    #[error("Fail to connect remote with tls")]
    TlsConnectError(std::io::Error),

    #[error("Invalid http request")]
    BadHttpError(std::io::Error),

    #[error("tokio::io::AsyncReadExt::read_until error")]
    ReadUntilError(std::io::Error),

    #[error("Stream returned error")]
    ReadStreamError(std::io::Error),

    #[error("Stream returned error")]
    WriteStreamError(std::io::Error),

    #[error("Fail to parse http")]
    HttpParseError(#[from] pext::FromUtf8Err),
}
