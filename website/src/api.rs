use crate::db::{check_whitelist, save_query, WhitelistedEntry};
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use log::warn;
use querying::asn::AsnInfo;
use querying::geoip::IpInfo;
use querying::lists::NetworkRecord;
use querying::target::Target;
use querying::{Check, CheckError, CheckVerdict, Checker};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::tokio::sync::RwLock;
use rocket::State;
use rocket_client_addr::ClientRealAddr;
use serde::Serialize;
use sqlx::postgres::PgPool;
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

pub type ApiRateLimiter =
    RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

pub fn build_rate_limiter(per_minute: u32) -> ApiRateLimiter {
    RateLimiter::keyed(Quota::per_minute(
        NonZeroU32::new(per_minute).expect("rate limit must be > 0"),
    ))
}

#[derive(Serialize)]
pub struct ApiCheckResponse {
    pub id: Option<String>,
    pub target: String,
    pub target_type: String,
    pub blocked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rkn_domain: Option<String>,
    pub ips: Vec<String>,
    pub blocked_subnets: Vec<String>,
    pub cdn_providers: HashMap<String, Vec<NetworkRecord>>,
    pub geo: IpInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn_info: Option<AsnInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whitelist: Option<WhitelistedEntry>,
}

fn build_response(
    id: Option<String>,
    target: &Target,
    check: Check,
    whitelist: Option<WhitelistedEntry>,
) -> ApiCheckResponse {
    let (blocked, rkn_domain, cdn_providers) = match check.verdict {
        CheckVerdict::Blocked {
            rkn_domain,
            cdn_provider_subnets,
        } => {
            let providers: HashMap<String, Vec<NetworkRecord>> = cdn_provider_subnets
                .into_iter()
                .map(|(k, v)| (k, v.into_iter().collect()))
                .collect();
            (true, rkn_domain, providers)
        }
        CheckVerdict::Clear => (false, None, HashMap::new()),
    };

    ApiCheckResponse {
        id,
        target: target.to_query(),
        target_type: target.readable_type().to_string(),
        blocked,
        rkn_domain,
        ips: check.ips.iter().map(|ip| ip.to_string()).collect(),
        blocked_subnets: check.rkn_subnets.iter().map(|n| n.to_string()).collect(),
        cdn_providers,
        geo: check.geo,
        asn_info: check.asn_info,
        whitelist,
    }
}

#[get("/check?<target>")]
pub async fn check(
    target: &str,
    checker: &State<Arc<RwLock<Checker>>>,
    addr: &ClientRealAddr,
    pool: &State<PgPool>,
    limiter: &State<Arc<ApiRateLimiter>>,
) -> Result<Json<ApiCheckResponse>, Status> {
    if limiter.check_key(&addr.ip).is_err() {
        return Err(Status::TooManyRequests);
    }

    let target = Target::from(target.trim());
    let check = checker.read().await.check(target.clone()).await;

    let mut db = pool
        .acquire()
        .await
        .map_err(|_| Status::InternalServerError)?;

    let id: Option<String> = if let Ok(check) = &check {
        match save_query(&mut *db, &target, check, addr, checker.read().await).await {
            Ok(id) => Some(id.to_string()),
            Err(e) => {
                warn!("api: failed to save check: {:?}", e);
                None
            }
        }
    } else {
        None
    };

    let whitelist: Option<WhitelistedEntry> = if let Target::Domain(domain) = &target {
        check_whitelist(domain, &mut *db)
            .await
            .map_err(|_| Status::InternalServerError)?
    } else {
        None
    };

    match check {
        Err(CheckError::NotFound) => Err(Status::NotFound),
        Ok(check) => Ok(Json(build_response(id, &target, check, whitelist))),
        Err(e) => {
            log::error!("api check failed {:?}", e);
            Err(Status::InternalServerError)
        }
    }
}
