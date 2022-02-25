use rcgen::BasicConstraints;
use rcgen::CertificateSigningRequest;
use rcgen::IsCa;
use rustls::{PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;

use rcgen::Certificate;
use rcgen::CertificateParams;
use rcgen::KeyPair;
use rcgen::SanType;

use endorphin::policy::TTIPolicy;
use endorphin::HashMap;

use tracing::info;
use tracing::instrument;

use std::ops::Add;
use std::sync::Arc;
use std::time::Duration;

pub struct Acceptor {
    map: HashMap<String, TlsAcceptor, TTIPolicy>,
    ca: Certificate,
}

impl Acceptor {
    pub fn new(ca: String, key: String) -> Self {
        let key = KeyPair::from_pem(&key).unwrap();
        let params = CertificateParams::from_ca_cert_pem(&ca, key).unwrap();

        let cert = Certificate::from_params(params).unwrap();

        Self {
            map: HashMap::new(TTIPolicy::new()),
            ca: cert,
        }
    }

    #[instrument(skip(self))]
    pub fn get(&mut self, host: String) -> &TlsAcceptor {
        let host = Self::normalize(host);

        if !self.map.contains_key(&host) {
            let mut params = Self::BaseCertParam(host.clone());

            let cert = Certificate::from_params(params).unwrap();

            let key = cert.serialize_private_key_der();
            let cert = cert.serialize_der_with_signer(&self.ca).unwrap();

            let cert = rustls::Certificate(cert);

            let cfg = ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(vec![cert], PrivateKey(key))
                .unwrap();

            let acceptor = TlsAcceptor::from(Arc::new(cfg));
            self.map
                .insert(host.clone(), acceptor, Duration::from_secs(3600));
        }

        self.map.get(&host).unwrap()
    }

    fn normalize(host: String) -> String {
        let first_dot = host.find('.').unwrap_or_default();
        format!("*{}", &host[first_dot..])
    }

    fn BaseCertParam(host: String) -> CertificateParams {
        use rcgen::{DnType, DnValue};

        let mut param = CertificateParams::default();

        param.alg = rcgen::SignatureAlgorithm::from_oid(&[1, 2, 840, 113549, 1, 1, 11]).unwrap();
        param.not_before = time::OffsetDateTime::now_utc();
        param.not_after =
            time::OffsetDateTime::now_utc().add(Duration::from_secs(3600 * 24 * 3650));
        param.subject_alt_names.push(SanType::DnsName(host.clone()));

        let mut d_name = rcgen::DistinguishedName::new();
        d_name.push(
            DnType::CountryName,
            DnValue::PrintableString("Yaler".to_string()),
        );
        d_name.push(
            DnType::StateOrProvinceName,
            DnValue::Utf8String("Yaler".to_string()),
        );
        d_name.push(
            DnType::LocalityName,
            DnValue::Utf8String("Yaler".to_string()),
        );
        d_name.push(
            DnType::OrganizationName,
            DnValue::Utf8String("Yaler".to_string()),
        );
        d_name.push(
            DnType::OrganizationalUnitName,
            DnValue::Utf8String("Yaler".to_string()),
        );
        d_name.push(DnType::CommonName, DnValue::Utf8String(host.clone()));

        param.distinguished_name = d_name;

        param.key_pair = KeyPair::from_der(include_bytes!("../cert/key.der")).ok();

        param
    }
}
