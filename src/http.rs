use async_trait::async_trait;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufStream},
    net::TcpStream,
};

use crate::error::Error;

#[async_trait]
pub trait ReadHttpExt {
    async fn read_until_header_end(&mut self, vec: &mut Vec<u8>) -> Result<usize, Error>;
}

#[async_trait]
impl ReadHttpExt for BufStream<TcpStream> {
    async fn read_until_header_end(&mut self, vec: &mut Vec<u8>) -> Result<usize, Error> {
        loop {
            let mut buf = Vec::new();
            self.read_until(b'\r', &mut buf)
                .await
                .map_err(|e| Error::ReadUntilError(e))?;

            let mut check = [0u8; 3];
            self.read_exact(&mut check)
                .await
                .map_err(|e| Error::BadHttpError(e))?;

            vec.append(&mut buf);
            vec.append(&mut check.to_vec());

            if check == [b'\n', b'\r', b'\n'] {
                break Ok(vec.len());
            }
        }
    }
}
