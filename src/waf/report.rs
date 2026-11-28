use reqwest::{StatusCode, Url};
use scraper::ElementRef;
use serde::Serialize;

const ALIBABA_BLOCK_MESSAGE: &str =
    "your request has been blocked as it may cause potential threats to the server's security";
const ALIBABA_ERROR_HOST: &str = "errors.aliyun.com";

/// An observation that can appear in output without affecting scan behavior.
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct PassiveWafObservation {
    #[serde(rename = "type")]
    pub(crate) name: &'static str,
    pub(crate) confidence: f32,
    pub(crate) evidence: &'static str,
}

/// Identify Alibaba Cloud's default block page from an existing response.
pub(crate) fn alibaba_block_page(status: StatusCode, body: &str) -> Option<PassiveWafObservation> {
    if status != StatusCode::METHOD_NOT_ALLOWED {
        return None;
    }
    if !body.to_ascii_lowercase().contains(ALIBABA_ERROR_HOST) {
        return None;
    }

    let document = crate::utils::html::parse_document_bounded(body);
    let root = document.root_element();
    let message = root.descendants().any(|node| {
        node.value()
            .as_text()
            .is_some_and(|text| text.to_ascii_lowercase().contains(ALIBABA_BLOCK_MESSAGE))
            && !node
                .ancestors()
                .filter_map(ElementRef::wrap)
                .any(|element| {
                    matches!(
                        element.value().name(),
                        "head" | "script" | "style" | "template"
                    )
                })
    });
    if !message {
        return None;
    }
    let reference = root
        .descendants()
        .filter_map(ElementRef::wrap)
        .any(|element| {
            let reference = match element.value().name() {
                "img" => element.attr("src"),
                "a" | "link" => element.attr("href"),
                _ => None,
            };
            reference.is_some_and(is_alibaba_error_url)
        });

    reference.then_some(PassiveWafObservation {
        name: "AlibabaCloud",
        confidence: 0.85,
        evidence: "Alibaba Cloud WAF default HTTP 405 block page",
    })
}

fn is_alibaba_error_url(reference: &str) -> bool {
    let reference = reference.trim();
    let url = if reference.starts_with("//") {
        Url::parse(&format!("https:{reference}"))
    } else {
        Url::parse(reference)
    };
    url.is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str() == Some(ALIBABA_ERROR_HOST)
            && url.username().is_empty()
            && url.password().is_none()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK_PAGE: &str = r#"<html><body>
        <img src="//errors.aliyun.com/images/block.png">
        <p>Sorry, your request has been blocked as it may cause potential threats to the server's security.</p>
        </body></html>"#;

    #[test]
    fn alibaba_block_page_reports_the_default_response() {
        for page in [
            BLOCK_PAGE.to_owned(),
            BLOCK_PAGE.replace("server's", "server&#39;s"),
            BLOCK_PAGE.replace("//errors.aliyun.com", "https://errors.aliyun.com"),
        ] {
            let observation = alibaba_block_page(StatusCode::METHOD_NOT_ALLOWED, &page)
                .expect("the three signals occur in the same response");
            assert_eq!(observation.name, "AlibabaCloud");
            assert_eq!(observation.confidence, 0.85);
        }
    }

    #[test]
    fn alibaba_block_page_requires_status_message_and_actual_host() {
        for status in [StatusCode::OK, StatusCode::TOO_MANY_REQUESTS] {
            assert!(alibaba_block_page(status, BLOCK_PAGE).is_none());
        }
        let bad_pages = [
            String::from("<h1>Method Not Allowed</h1>"),
            String::from(r#"<a href="https://errors.aliyun.com/">Alibaba help</a>"#),
            BLOCK_PAGE.replace("errors.aliyun.com", "errors.aliyun.com.example.org"),
            BLOCK_PAGE.replace("errors.aliyun.com", "errors.aliyun.com@example.org"),
            BLOCK_PAGE.replace("errors.aliyun.com", "user@errors.aliyun.com"),
            BLOCK_PAGE.replace(r#"src="//errors.aliyun.com"#, r#"src="/errors.aliyun.com"#),
            BLOCK_PAGE.replace("<p>", "<!--").replace("</p>", "-->"),
            BLOCK_PAGE
                .replace("<p>", "<script>")
                .replace("</p>", "</script>"),
        ];
        for page in bad_pages {
            assert!(
                alibaba_block_page(StatusCode::METHOD_NOT_ALLOWED, &page).is_none(),
                "{page}"
            );
        }
    }
}
