use std::collections::BTreeMap;
use tokio::time::timeout;
use::std::time::Duration;

use prost_types::value::Kind;
use prost_types::Struct;
use tonic::codegen::InterceptedService;
use tracing::{info, instrument};

use crate::identity::auth::AuthSource;
use crate::identity::manager::Identity;
use crate::identity::{Error, self};
use crate::tls;
use crate::tls::TlsGrpcChannel;
use crate::xds::istio::ca::istio_certificate_service_client::IstioCertificateServiceClient;
use crate::xds::istio::ca::IstioCertificateRequest;

#[derive(Clone, Debug)]
pub struct CaClient {
    pub client: IstioCertificateServiceClient<InterceptedService<TlsGrpcChannel, AuthSource>>,
}

impl CaClient {
    pub fn new(auth: AuthSource) -> CaClient {
        let address = if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
            "https://istiod.istio-system:15012"
        } else {
            "https://localhost:15012"
        };
        let svc = tls::grpc_connector(address).unwrap();
        let client = IstioCertificateServiceClient::with_interceptor(svc, auth);
        CaClient { client }
    }

    #[instrument(skip_all)]
    pub async fn fetch_certificate(&mut self, id: Identity) -> Result<tls::Certs, Error> {
        let cs = tls::CsrOptions {
            san: id.to_string(),
        }
        .generate()?;
        let csr: Vec<u8> = cs.csr;
        let pkey = cs.pkey;

        let csr = std::str::from_utf8(&csr).map_err(Error::Utf8)?.to_string();
        let req = IstioCertificateRequest {
            csr,
            validity_duration: 60 * 60 * 24, // 24 hours
            metadata: Some(Struct {
                fields: BTreeMap::from([(
                    "ImpersonatedIdentity".into(),
                    prost_types::Value {
                        kind: Some(Kind::StringValue(id.to_string())),
                    },
                )]),
            }),
        };
        info!("Sending ca request for id {:?}\nreq: {:?}", id, req);
        let resp_res = self.client.create_certificate(req).await;
        info!("response: {:?}", resp_res);
        let resp;
        match resp_res {
            Err(e) => {
                return Err(identity::Error::SigningRequest(e));
            }
            Ok(v) => {
                resp = v.into_inner();
            }
        }
        Ok(tls::cert_from(
            &pkey,
            resp.cert_chain.first().unwrap().as_bytes(),
        ))
    }
}
