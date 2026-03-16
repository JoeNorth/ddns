use crate::pp::{self, PP};
use crate::provider::IpType;
use bollard::query_parameters::ListContainersOptions;
use bollard::Docker;
use std::collections::HashMap;

const DOCKER_LABEL_KEY: &str = "cloudflare-ddns.domain";
const DOCKER_TIMEOUT: u64 = 10;

/// Discover domains from Docker container labels.
///
/// Queries the Docker socket for running containers with the `cloudflare-ddns.domain` label.
/// Returns domains for both IPv4 and IPv6 (matching `DOMAINS` env var behavior).
/// On any error, logs a warning and returns an empty map.
pub async fn discover_docker_domains(
    socket_path: Option<&str>,
    ppfmt: &PP,
) -> HashMap<IpType, Vec<String>> {
    let docker = match connect(socket_path) {
        Ok(d) => d,
        Err(e) => {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("Failed to connect to Docker: {e}"),
            );
            return HashMap::new();
        }
    };

    let mut filters = HashMap::new();
    filters.insert("label".to_string(), vec![DOCKER_LABEL_KEY.to_string()]);

    let options = ListContainersOptions {
        filters: Some(filters),
        ..Default::default()
    };

    let containers = match docker.list_containers(Some(options)).await {
        Ok(c) => c,
        Err(e) => {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("Failed to list Docker containers: {e}"),
            );
            return HashMap::new();
        }
    };

    let domains = extract_domains(&containers, ppfmt);

    if domains.is_empty() {
        ppfmt.infof(pp::EMOJI_DOCKER, "No domains discovered from Docker labels");
        return HashMap::new();
    }

    ppfmt.infof(
        pp::EMOJI_DOCKER,
        &format!(
            "Discovered {} domain(s) from Docker labels: {}",
            domains.len(),
            domains.join(", ")
        ),
    );

    let mut result = HashMap::new();
    result.insert(IpType::V4, domains.clone());
    result.insert(IpType::V6, domains);
    result
}

fn connect(socket_path: Option<&str>) -> Result<Docker, bollard::errors::Error> {
    match socket_path {
        Some(path) => {
            Docker::connect_with_socket(path, DOCKER_TIMEOUT, &bollard::API_DEFAULT_VERSION)
        }
        None => Docker::connect_with_socket_defaults(),
    }
}

/// Extract and validate domain strings from container labels.
/// Exported as a pure function for testability.
pub fn extract_domains(
    containers: &[bollard::models::ContainerSummary],
    ppfmt: &PP,
) -> Vec<String> {
    let mut domains = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for container in containers {
        let labels = match &container.labels {
            Some(l) => l,
            None => continue,
        };

        let domain = match labels.get(DOCKER_LABEL_KEY) {
            Some(d) => d.trim().to_lowercase(),
            None => continue,
        };

        if domain.is_empty() {
            let name = container_name(container);
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("Container {name} has empty {DOCKER_LABEL_KEY} label, skipping"),
            );
            continue;
        }

        if seen.insert(domain.clone()) {
            domains.push(domain);
        }
    }

    domains
}

fn container_name(container: &bollard::models::ContainerSummary) -> String {
    container
        .names
        .as_ref()
        .and_then(|names| names.first())
        .cloned()
        .unwrap_or_else(|| {
            container
                .id
                .as_ref()
                .map(|id| id.chars().take(12).collect())
                .unwrap_or_else(|| "<unknown>".to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::ContainerSummary;

    fn make_container(name: &str, domain: Option<&str>) -> ContainerSummary {
        let labels = domain.map(|d| {
            let mut m = HashMap::new();
            m.insert(DOCKER_LABEL_KEY.to_string(), d.to_string());
            m
        });

        ContainerSummary {
            names: Some(vec![format!("/{name}")]),
            labels,
            ..Default::default()
        }
    }

    #[test]
    fn test_extract_domains_basic() {
        let ppfmt = PP::default_pp();
        let containers = vec![
            make_container("web", Some("example.com")),
            make_container("api", Some("api.example.com")),
        ];
        let domains = extract_domains(&containers, &ppfmt);
        assert_eq!(domains, vec!["example.com", "api.example.com"]);
    }

    #[test]
    fn test_extract_domains_dedup() {
        let ppfmt = PP::default_pp();
        let containers = vec![
            make_container("web1", Some("example.com")),
            make_container("web2", Some("example.com")),
        ];
        let domains = extract_domains(&containers, &ppfmt);
        assert_eq!(domains, vec!["example.com"]);
    }

    #[test]
    fn test_extract_domains_skips_empty() {
        let ppfmt = PP::default_pp();
        let containers = vec![
            make_container("web", Some("example.com")),
            make_container("bad", Some("")),
            make_container("spaces", Some("   ")),
        ];
        let domains = extract_domains(&containers, &ppfmt);
        assert_eq!(domains, vec!["example.com"]);
    }

    #[test]
    fn test_extract_domains_lowercases() {
        let ppfmt = PP::default_pp();
        let containers = vec![make_container("web", Some("Example.COM"))];
        let domains = extract_domains(&containers, &ppfmt);
        assert_eq!(domains, vec!["example.com"]);
    }

    #[test]
    fn test_extract_domains_no_label() {
        let ppfmt = PP::default_pp();
        let containers = vec![
            make_container("web", Some("example.com")),
            ContainerSummary {
                names: Some(vec!["/nolabel".to_string()]),
                labels: Some(HashMap::new()),
                ..Default::default()
            },
        ];
        let domains = extract_domains(&containers, &ppfmt);
        assert_eq!(domains, vec!["example.com"]);
    }

    #[test]
    fn test_extract_domains_no_labels_map() {
        let ppfmt = PP::default_pp();
        let containers = vec![ContainerSummary {
            names: Some(vec!["/nolabels".to_string()]),
            labels: None,
            ..Default::default()
        }];
        let domains = extract_domains(&containers, &ppfmt);
        assert!(domains.is_empty());
    }

    #[test]
    fn test_extract_domains_empty_containers() {
        let ppfmt = PP::default_pp();
        let domains = extract_domains(&[], &ppfmt);
        assert!(domains.is_empty());
    }

    #[test]
    fn test_container_name_from_names() {
        let c = make_container("myapp", None);
        assert_eq!(container_name(&c), "/myapp");
    }

    #[test]
    fn test_container_name_fallback_to_id() {
        let c = ContainerSummary {
            id: Some("abcdef1234567890".to_string()),
            names: None,
            labels: None,
            ..Default::default()
        };
        assert_eq!(container_name(&c), "abcdef123456");
    }

    #[test]
    fn test_container_name_unknown() {
        let c = ContainerSummary {
            id: None,
            names: None,
            labels: None,
            ..Default::default()
        };
        assert_eq!(container_name(&c), "<unknown>");
    }
}
