mod acceptor;
mod error;
mod http;
mod server;

use crate::server::Server;

use acceptor::Acceptor;
use rustls::{Certificate, PrivateKey, ServerConfig};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let acceptor = Acceptor::new(
        include_str!("../cert/root.crt").to_string(),
        include_str!("../cert/key.pem").to_string(),
    );

    let mut server = Server::bind("127.0.0.1:5333", root_store, acceptor)
        .await
        .unwrap();
    server.run().await.unwrap();
}
