pub mod check_dom_verification;
pub mod check_reflection;
pub mod common;

use crate::scanning::check_dom_verification::check_dom_verification;
use crate::scanning::check_reflection::check_reflection;
use crate::scanning::common::get_xss_payloads;
use crate::target_parser::Target;
use std::sync::Arc;
use tokio::sync::Semaphore;

pub async fn run_scanning(target: &Target) {
    let semaphore = Arc::new(Semaphore::new(target.workers));
    let payloads = get_xss_payloads();

    let mut handles = vec![];

    for param in &target.reflection_params {
        for &payload in payloads {
            let semaphore_clone = semaphore.clone();
            let param_clone = param.clone();
            let target_clone = (*target).clone(); // Clone target for each task

            let handle = tokio::spawn(async move {
                let _permit = semaphore_clone.acquire().await.unwrap();
                let reflected = check_reflection(&target_clone, &param_clone, payload).await;
                if reflected {
                    check_dom_verification(&target_clone, &param_clone, payload).await;
                }
            });
            handles.push(handle);
        }
    }

    for handle in handles {
        handle.await.unwrap();
    }

    println!("XSS scanning completed for target: {}", target.url);
}
