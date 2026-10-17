//! Discovery surface: cookie. See the module docs in `mod.rs`.

use super::*;

pub async fn check_cookie_discovery(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let arc_target = Arc::new(target.clone());
    let client = target.build_client_or_default();
    let test_value = crate::scanning::markers::bracketed_marker();

    let mut handles = vec![];

    // Under `--skip-reflection-cookie` the blanket sweep over supplied cookies
    // is off, but cookies named explicitly via `-p name:cookie` are explicit
    // injection points and still get probed.
    let explicit_only: Option<Vec<String>> = if args.skip_reflection_cookie {
        Some(explicit_param_names(&args.param, "cookie"))
    } else {
        None
    };

    for (cookie_name, cookie_value) in &target.cookies {
        if let Some(ref allow) = explicit_only
            && !allow.iter().any(|n| n == cookie_name)
        {
            continue;
        }
        let client_clone = client.clone();
        let url = target.url.clone();
        let cookies = target.cookies.clone();
        let data = target.data.clone();
        let parsed_method = target.parse_method();
        let cookie_name = cookie_name.clone();
        let cookie_value = cookie_value.clone();
        let probed_name = cookie_name.clone();
        let target_clone = arc_target.clone();

        let handle = crate::parameter_analysis::spawn_reflection_probe(
            semaphore.clone(),
            target.delay,
            None,
            move || {
                // Compose cookie header overriding the probed cookie while preserving others
                let others =
                    crate::utils::compose_cookie_header_excluding(&cookies, Some(&probed_name));
                let cookie_header = match others {
                    Some(s) => format!("{}; {}={}", s, probed_name, test_value),
                    None => format!("{}={}", probed_name, test_value),
                };
                Some(crate::utils::build_request_with_cookie(
                    &client_clone,
                    &target_clone,
                    parsed_method,
                    url,
                    data,
                    Some(cookie_header),
                ))
            },
            move |text| {
                Param::new(
                    cookie_name,
                    cookie_value,
                    crate::parameter_analysis::Location::Header,
                )
                .with_cookie_identity(true)
                .with_reflection_analysis(text)
            },
        );
        handles.push(handle);
    }

    extend_with_joined(&reflection_params, handles).await;
}
