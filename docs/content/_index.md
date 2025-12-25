+++
template = "landing.html"

[extra.hero]
title = "Welcome to Dalfox"
badge = "v3.0.0"
description = "Powerful open-source XSS scanner and utility focused on automation"
image = "/images/preview.jpg" # Background image
cta_buttons = [
    { text = "Get Started", url = "/getting_started/installation", style = "primary" },
    { text = "View on GitHub", url = "https://github.com/hahwul/dalfox", style = "secondary" },
]

[extra.features_section]
title = "Essential Features"
description = "Discover Dalfox's essential features for comprehensive attack surface detection and analysis."

[[extra.features]]
title = "Multiple Scanning Modes"
desc = "URL, File, Pipe, Raw HTTP, and Server modes for flexible testing workflows and integration with your tools."
icon = "fa-solid fa-network-wired"

[[extra.features]]
title = "Parameter Analysis"
desc = "Automatic parameter discovery across query, body, headers, cookies, and path segments with advanced mining techniques."
icon = "fa-solid fa-magnifying-glass"

[[extra.features]]
title = "XSS Detection"
desc = "Detect Reflected, Stored, and DOM-based XSS with context-aware payload generation and DOM/AST verification."
icon = "fa-solid fa-shield-halved"

[[extra.features]]
title = "Blind XSS Support"
desc = "Built-in blind XSS testing with callback URL support for detecting out-of-band vulnerabilities."
icon = "fa-solid fa-eye-slash"

[[extra.features]]
title = "High Performance"
desc = "Built with Rust for maximum speed and efficiency, featuring concurrent scanning with smart rate limiting and host grouping."
icon = "fa-solid fa-bolt"

[[extra.features]]
title = "MCP Server Support"
desc = "Integrates with AI models via Model Context Protocol for intelligent XSS analysis and automated testing workflows."
icon = "fa-solid fa-robot"

[extra.final_cta_section]
title = "Contributing"
description = "Dalfox is an open-source project made with ❤️. If you want to contribute to this project, please see CONTRIBUTING.md and submit a pull request with your cool content!"
button = { text = "View Contributing Guide", url = "https://github.com/hahwul/dalfox/blob/main/CONTRIBUTING.md" }
+++
