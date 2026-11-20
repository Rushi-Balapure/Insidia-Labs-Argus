# Security

## Reporting a vulnerability

Email [insidialabs@gmail.com](mailto:insidialabs@gmail.com). Please do not open a public issue for a vulnerability in Insidia itself.

Include what you ran, the version or commit, and the impact. We will reply with a plan and a credit, if you want one, once a fix is ready.

## Scanning other people's systems

Insidia is a security testing tool. Point it only at systems you are allowed to test.

- The CLI scans hosts listed in `insidia.yaml`.
- Any host other than localhost needs `authorized: true` from the person who owns the target.
- Do not use Insidia Cloud, the hosted models, or a local run to attack a system you do not have permission to test.

## Where a scan may connect

Insidia's own client dials an address the hostname resolved to, then checks that address. On the default localhost scope every address must be loopback. For an authorized host, only the addresses recorded at the start of the scan may be used later.

Wrapped engines are started with `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` aimed at a proxy on 127.0.0.1. The proxy allows an in-scope host only after the same address check. Nuclei, ZAP, httpx, katana, dalfox, and garak are also passed their own proxy setting. A blocked attempt fails that check.

Those variables are advisory. A program that opens its own socket and ignores them is not confined. ZAP may still skip the proxy for localhost. promptfoo's own process may ignore it, except for the provider script Insidia writes. PyRIT and deepteam are confined where they use HTTP libraries that honor the environment. Trivy, gitleaks, osv-scanner, NuGuard, mcp-scanner, and skillspector are confined only when they honor the variables. Network namespaces are not used.

## Secrets

Do not commit credentials, customer data, or scan evidence. Production configuration stays out of this repository.
