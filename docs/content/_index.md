+++
template = "landing.html"

[extra.hero]
title = "Welcome to Dalfox"
badge = "v3.0.0"
description = "Powerful open-source XSS scanner and utility focused on automation"
image = "/images/preview.jpg" # Background image
cta_buttons = [
    { text = "Get Started", url = "/get_started/installation", style = "primary" },
    { text = "View on GitHub", url = "https://github.com/hahwul/dalfox", style = "secondary" },
]

[[extra.features]]
title = "JWT/JWE Encoding & Decoding"
desc = "Encode and decode JWT and JWE tokens with support for multiple algorithms, custom headers, and DEFLATE compression."
icon = "fa-solid fa-code"

[[extra.features]]
title = "Signature Verification"
desc = "Verify JWT signatures using secrets or keys for symmetric and asymmetric algorithms with expiration validation."
icon = "fa-solid fa-shield-check"

[[extra.features]]
title = "Advanced Cracking"
desc = "Crack JWT secrets using dictionary attacks or brute force methods with support for compressed tokens."
icon = "fa-solid fa-key"

[[extra.features]]
title = "Attack Payload Generation"
desc = "Generate various JWT attack payloads including none algorithm, algorithm confusion, and header manipulation attacks."
icon = "fa-solid fa-bomb"

[[extra.features]]
title = "High Performance"
desc = "Built with Rust for maximum speed and efficiency, leveraging parallel processing for intensive operations."
icon = "fa-solid fa-bolt"

[[extra.features]]
title = "MCP Server Support"
desc = "Integrates with AI models via Model Context Protocol for intelligent JWT analysis and testing."
icon = "fa-solid fa-robot"

[extra.final_cta_section]
title = "Contributing"
description = "JWT-HACK is an open-source project made with ❤️. If you want to contribute to this project, please see CONTRIBUTING.md and submit a pull request with your cool content!"
button = { text = "View Contributing Guide", url = "https://github.com/hahwul/jwt-hack/blob/main/CONTRIBUTING.md" }
+++
