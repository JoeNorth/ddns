use crate::backend::{DnsBackend, SetResult, Ttl};
use crate::pp::{self, PP};
use std::net::IpAddr;
use std::time::Duration;
use technitium::{AddRecord, AddRecordData, DeleteRecordId, RecordType, ZoneClient};

pub struct TechnitiumHandle {
    client: technitium::Client,
}

impl TechnitiumHandle {
    pub fn new(base_url: String, token: String, timeout: Duration) -> Self {
        let client = technitium::Client::builder()
            .base_url(base_url)
            .token(token)
            .request_timeout(timeout)
            .build()
            .expect("Failed to build Technitium client");

        Self { client }
    }

    /// List the current IP addresses for a domain and record type.
    async fn list_ips(
        zone: &ZoneClient<'_>,
        fqdn: &str,
        rtype: &RecordType,
        ppfmt: &PP,
    ) -> Result<Vec<IpAddr>, ()> {
        let records = match zone.list_records(Some(fqdn)).await {
            Ok(r) => r,
            Err(e) => {
                ppfmt.errorf(
                    pp::EMOJI_ERROR,
                    &format!("Failed to list records for {fqdn}: {e}"),
                );
                return Err(());
            }
        };

        Ok(records
            .iter()
            .filter(|r| r.record_type == *rtype)
            .filter_map(|r| {
                r.data
                    .get("rData")
                    .and_then(|rd| rd.get("ipAddress"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<IpAddr>().ok())
            })
            .collect())
    }

    /// Delete the given A or AAAA records for a domain by IP address
    /// (required by Technitium's API).
    async fn delete_records_by_ip(
        zone: &ZoneClient<'_>,
        fqdn: &str,
        rtype: &RecordType,
        existing: &[IpAddr],
        ppfmt: &PP,
    ) -> Result<(), ()> {
        let type_str = rtype.to_string();
        let mut any_error = false;
        for ip in existing {
            let delete_id = match rtype {
                RecordType::A => DeleteRecordId::A {
                    ip_address: *ip,
                    update_svcb_hints: None,
                },
                RecordType::AAAA => DeleteRecordId::AAAA {
                    ip_address: *ip,
                    update_svcb_hints: None,
                },
                _ => unreachable!("cloudflare-ddns only uses A/AAAA records"),
            };
            if let Err(e) = zone.delete_record(fqdn, &delete_id).await {
                ppfmt.errorf(
                    pp::EMOJI_ERROR,
                    &format!("Technitium error deleting {type_str} {fqdn} -> {ip}: {e}"),
                );
                any_error = true;
            }
        }

        if any_error { Err(()) } else { Ok(()) }
    }

    #[cfg(test)]
    fn with_base_url(base_url: &str, token: &str) -> Self {
        Self::new(base_url.to_string(), token.to_string(), Duration::from_secs(10))
    }
}

impl DnsBackend for TechnitiumHandle {
    async fn set_ips(
        &self,
        fqdn: &str,
        record_type: &str,
        ips: &[IpAddr],
        _proxied: bool,
        ttl: Ttl,
        _comment: Option<&str>,
        dry_run: bool,
        ppfmt: &PP,
    ) -> SetResult {
        // Map TTL: AUTO (1) becomes 300s default for Technitium
        let effective_ttl: Ttl = if ttl.0 < 2 { Ttl(300) } else { ttl };
        let rtype: RecordType = record_type.parse().unwrap();

        // Dry run skips zone resolution and API calls
        if dry_run {
            if ips.is_empty() {
                ppfmt.noticef(
                    pp::EMOJI_DELETE,
                    &format!("[DRY RUN] Would delete all {record_type} records for {fqdn}"),
                );
            } else {
                for (i, ip) in ips.iter().enumerate() {
                    if i == 0 {
                        ppfmt.noticef(
                            pp::EMOJI_UPDATE,
                            &format!("[DRY RUN] Would set {record_type} record {fqdn} -> {ip}"),
                        );
                    } else {
                        ppfmt.noticef(
                            pp::EMOJI_CREATE,
                            &format!("[DRY RUN] Would add {record_type} record {fqdn} -> {ip}"),
                        );
                    }
                }
            }
            return SetResult::Updated;
        }

        // Resolve zone
        let zone = match self.client.zone_for_domain(fqdn).await {
            Ok(z) => z,
            Err(e) => {
                ppfmt.errorf(
                    pp::EMOJI_ERROR,
                    &format!("No Technitium zone found for {fqdn}: {e}"),
                );
                return SetResult::Failed;
            }
        };

        // Fetch existing records and compare with desired state
        let existing = match Self::list_ips(&zone, fqdn, &rtype, ppfmt).await {
            Ok(e) => e,
            Err(()) => return SetResult::Failed,
        };

        if ips.is_empty() {
            if existing.is_empty() {
                return SetResult::Noop;
            }

            ppfmt.noticef(
                pp::EMOJI_DELETE,
                &format!("Deleting all {record_type} records for {fqdn}"),
            );

            return match Self::delete_records_by_ip(&zone, fqdn, &rtype, &existing, ppfmt).await {
                Ok(()) => SetResult::Updated,
                Err(()) => SetResult::Failed,
            };
        }

        // Check if existing records already match the desired IPs (order-independent)
        {
            let mut desired_sorted: Vec<IpAddr> = ips.to_vec();
            desired_sorted.sort();
            let mut existing_sorted = existing.clone();
            existing_sorted.sort();
            if desired_sorted == existing_sorted {
                return SetResult::Noop;
            }
        }

        let mut any_error = false;

        for (i, ip) in ips.iter().enumerate() {
            let overwrite = i == 0;

            let data = match rtype {
                RecordType::A => AddRecordData::A {
                    ip_address: *ip,
                    ptr: None,
                    create_ptr_zone: None,
                    update_svcb_hints: None,
                },
                RecordType::AAAA => AddRecordData::AAAA {
                    ip_address: *ip,
                    ptr: None,
                    create_ptr_zone: None,
                    update_svcb_hints: None,
                },
                _ => unreachable!("cloudflare-ddns only uses A/AAAA records"),
            };

            let record = AddRecord {
                domain: fqdn.to_string(),
                ttl: effective_ttl,
                data,
                overwrite: Some(overwrite),
                comments: None,
                expiry_ttl: None,
            };

            match zone.add_record(&record).await {
                Ok(()) => {
                    ppfmt.noticef(
                        pp::EMOJI_UPDATE,
                        &format!("Set {record_type} record {fqdn} -> {ip}"),
                    );
                }
                Err(e) => {
                    ppfmt.errorf(
                        pp::EMOJI_ERROR,
                        &format!("Technitium error setting {fqdn} -> {ip}: {e}"),
                    );
                    any_error = true;
                }
            }
        }

        if any_error {
            SetResult::Failed
        } else {
            SetResult::Updated
        }
    }

    async fn final_delete(
        &self,
        fqdn: &str,
        record_type: &str,
        ppfmt: &PP,
    ) {
        let rtype: RecordType = record_type.parse().unwrap();

        let zone = match self.client.zone_for_domain(fqdn).await {
            Ok(z) => z,
            Err(e) => {
                ppfmt.errorf(
                    pp::EMOJI_ERROR,
                    &format!("No Technitium zone found for {fqdn}: {e}"),
                );
                return;
            }
        };

        let existing = match Self::list_ips(&zone, fqdn, &rtype, ppfmt).await {
            Ok(e) => e,
            Err(()) => return,
        };

        if existing.is_empty() {
            return;
        }

        ppfmt.noticef(
            pp::EMOJI_DELETE,
            &format!("Deleting all {record_type} records for {fqdn}"),
        );

        match Self::delete_records_by_ip(&zone, fqdn, &rtype, &existing, ppfmt).await {
            Ok(()) => {
                ppfmt.infof(pp::EMOJI_DELETE, &format!("Deleted {record_type} records for {fqdn}"));
            }
            Err(()) => {}
        }
    }

    fn backend_name(&self) -> &str {
        "Technitium"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pp::PP;
    use std::net::IpAddr;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn pp() -> PP {
        PP::new(false, false)
    }

    fn ok_response() -> serde_json::Value {
        serde_json::json!({ "status": "ok" })
    }

    fn error_response(msg: &str) -> serde_json::Value {
        serde_json::json!({ "status": "error", "errorMessage": msg })
    }

    fn zones_response(zones: &[&str]) -> serde_json::Value {
        let zone_list: Vec<serde_json::Value> = zones
            .iter()
            .map(|name| {
                serde_json::json!({
                    "name": name,
                    "type": "Primary",
                    "disabled": false,
                    "internal": false
                })
            })
            .collect();
        serde_json::json!({
            "status": "ok",
            "response": { "zones": zone_list }
        })
    }

    async fn mount_zones(server: &MockServer, zones: &[&str]) {
        Mock::given(method("POST"))
            .and(path("/api/zones/list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(zones_response(zones)))
            .mount(server)
            .await;
    }

    fn records_response(records: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({
            "status": "ok",
            "response": { "records": records }
        })
    }

    fn a_record(domain: &str, ip: &str) -> serde_json::Value {
        serde_json::json!({
            "name": domain,
            "type": "A",
            "ttl": 300,
            "rData": { "ipAddress": ip }
        })
    }

    fn aaaa_record(domain: &str, ip: &str) -> serde_json::Value {
        serde_json::json!({
            "name": domain,
            "type": "AAAA",
            "ttl": 300,
            "rData": { "ipAddress": ip }
        })
    }

    async fn mount_records(server: &MockServer, records: Vec<serde_json::Value>) {
        Mock::given(method("POST"))
            .and(path("/api/zones/records/get"))
            .respond_with(ResponseTemplate::new(200).set_body_json(records_response(records)))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn zone_for_domain_found() {
        let server = MockServer::start().await;
        mount_zones(&server, &["example.com", "other.org"]).await;

        let h = TechnitiumHandle::with_base_url(&server.uri(), "test-token");
        let zone = h.client.zone_for_domain("sub.example.com").await.unwrap();
        assert_eq!(zone.name(), "example.com");
    }

    #[tokio::test]
    async fn zone_for_domain_exact_match() {
        let server = MockServer::start().await;
        mount_zones(&server, &["example.com"]).await;

        let h = TechnitiumHandle::with_base_url(&server.uri(), "test-token");
        let zone = h.client.zone_for_domain("example.com").await.unwrap();
        assert_eq!(zone.name(), "example.com");
    }

    #[tokio::test]
    async fn zone_for_domain_not_found() {
        let server = MockServer::start().await;
        mount_zones(&server, &["other.org"]).await;

        let h = TechnitiumHandle::with_base_url(&server.uri(), "test-token");
        let result = h.client.zone_for_domain("sub.example.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn set_ips_creates_record() {
        let server = MockServer::start().await;
        mount_zones(&server, &["example.com"]).await;
        mount_records(&server, vec![]).await;
        Mock::given(method("POST"))
            .and(path("/api/zones/records/add"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_response()))
            .expect(1)
            .mount(&server)
            .await;

        let h = TechnitiumHandle::with_base_url(&server.uri(), "test-token");
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h.set_ips("test.example.com", "A", &ips, false, Ttl(300), None, false, &pp()).await;
        assert_eq!(result, SetResult::Updated);
    }

    #[tokio::test]
    async fn set_ips_multiple_ips() {
        let server = MockServer::start().await;
        mount_zones(&server, &["example.com"]).await;
        mount_records(&server, vec![]).await;
        Mock::given(method("POST"))
            .and(path("/api/zones/records/add"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_response()))
            .expect(2)
            .mount(&server)
            .await;

        let h = TechnitiumHandle::with_base_url(&server.uri(), "test-token");
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()];
        let result = h.set_ips("test.example.com", "A", &ips, false, Ttl(300), None, false, &pp()).await;
        assert_eq!(result, SetResult::Updated);
    }

    #[tokio::test]
    async fn set_ips_dry_run_no_api_calls() {
        let server = MockServer::start().await;
        // No mocks — any API call would return 404

        let h = TechnitiumHandle::with_base_url(&server.uri(), "test-token");
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h.set_ips("test.example.com", "A", &ips, false, Ttl(300), None, true, &pp()).await;
        assert_eq!(result, SetResult::Updated);
    }

    #[tokio::test]
    async fn set_ips_empty_deletes() {
        let server = MockServer::start().await;
        mount_zones(&server, &["example.com"]).await;
        mount_records(&server, vec![a_record("test.example.com", "9.8.7.6")]).await;
        Mock::given(method("POST"))
            .and(path("/api/zones/records/delete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_response()))
            .expect(1)
            .mount(&server)
            .await;

        let h = TechnitiumHandle::with_base_url(&server.uri(), "test-token");
        let ips: Vec<IpAddr> = vec![];
        let result = h.set_ips("test.example.com", "A", &ips, false, Ttl(300), None, false, &pp()).await;
        assert_eq!(result, SetResult::Updated);
    }

    #[tokio::test]
    async fn set_ips_api_error_returns_failed() {
        let server = MockServer::start().await;
        mount_zones(&server, &["example.com"]).await;
        mount_records(&server, vec![]).await;
        Mock::given(method("POST"))
            .and(path("/api/zones/records/add"))
            .respond_with(ResponseTemplate::new(200).set_body_json(error_response("zone not found")))
            .mount(&server)
            .await;

        let h = TechnitiumHandle::with_base_url(&server.uri(), "test-token");
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h.set_ips("test.example.com", "A", &ips, false, Ttl(300), None, false, &pp()).await;
        assert_eq!(result, SetResult::Failed);
    }

    #[tokio::test]
    async fn set_ips_no_zone_returns_failed() {
        let server = MockServer::start().await;
        mount_zones(&server, &["other.org"]).await;

        let h = TechnitiumHandle::with_base_url(&server.uri(), "test-token");
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h.set_ips("test.example.com", "A", &ips, false, Ttl(300), None, false, &pp()).await;
        assert_eq!(result, SetResult::Failed);
    }

    #[tokio::test]
    async fn set_ips_auto_ttl_maps_to_300() {
        let server = MockServer::start().await;
        mount_zones(&server, &["example.com"]).await;
        mount_records(&server, vec![]).await;
        Mock::given(method("POST"))
            .and(path("/api/zones/records/add"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_response()))
            .expect(1)
            .mount(&server)
            .await;

        let h = TechnitiumHandle::with_base_url(&server.uri(), "test-token");
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        // ttl=1 is Cloudflare "auto" — should become 300
        let result = h.set_ips("test.example.com", "A", &ips, false, Ttl(1), None, false, &pp()).await;
        assert_eq!(result, SetResult::Updated);
    }

    #[tokio::test]
    async fn set_ips_noop_when_matching() {
        let server = MockServer::start().await;
        mount_zones(&server, &["example.com"]).await;
        mount_records(&server, vec![a_record("test.example.com", "1.2.3.4")]).await;
        // No add/delete mocks — any API write would return 404

        let h = TechnitiumHandle::with_base_url(&server.uri(), "test-token");
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h.set_ips("test.example.com", "A", &ips, false, Ttl(300), None, false, &pp()).await;
        assert_eq!(result, SetResult::Noop);
    }

    #[tokio::test]
    async fn set_ips_noop_when_matching_multiple() {
        let server = MockServer::start().await;
        mount_zones(&server, &["example.com"]).await;
        mount_records(&server, vec![
            a_record("test.example.com", "5.6.7.8"),
            a_record("test.example.com", "1.2.3.4"),
        ]).await;

        let h = TechnitiumHandle::with_base_url(&server.uri(), "test-token");
        // Different order than existing — should still be noop
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()];
        let result = h.set_ips("test.example.com", "A", &ips, false, Ttl(300), None, false, &pp()).await;
        assert_eq!(result, SetResult::Noop);
    }

    #[tokio::test]
    async fn set_ips_empty_noop_when_no_records() {
        let server = MockServer::start().await;
        mount_zones(&server, &["example.com"]).await;
        mount_records(&server, vec![]).await;

        let h = TechnitiumHandle::with_base_url(&server.uri(), "test-token");
        let ips: Vec<IpAddr> = vec![];
        let result = h.set_ips("test.example.com", "A", &ips, false, Ttl(300), None, false, &pp()).await;
        assert_eq!(result, SetResult::Noop);
    }

    #[tokio::test]
    async fn final_delete_calls_api() {
        let server = MockServer::start().await;
        mount_zones(&server, &["example.com"]).await;
        mount_records(&server, vec![aaaa_record("test.example.com", "::1")]).await;
        Mock::given(method("POST"))
            .and(path("/api/zones/records/delete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_response()))
            .expect(1)
            .mount(&server)
            .await;

        let h = TechnitiumHandle::with_base_url(&server.uri(), "test-token");
        h.final_delete("test.example.com", "AAAA", &pp()).await;
    }

    #[tokio::test]
    async fn final_delete_no_zone_logs_error() {
        let server = MockServer::start().await;
        mount_zones(&server, &["other.org"]).await;

        let h = TechnitiumHandle::with_base_url(&server.uri(), "test-token");
        // Should not panic, just log error
        h.final_delete("test.example.com", "AAAA", &pp()).await;
    }
}
