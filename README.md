# QuantaSentry

> Cryptographic inventory and post-quantum migration-readiness reporting from source/configuration evidence.

**Status:** MVP scaffold / research prototype. Not production-certified.

## Features
- Detect selected legacy cryptographic API and algorithm references in source.
- Record file/line evidence.
- Generate migration-review inventory.
- Keep algorithm detection separate from compliance claims.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -e ".[dev]"
pytest
```

## Safety and scope
Static inventory only. A detected algorithm name does not prove a live cryptographic use or establish exploitability. No endpoint probing or cryptographic downgrade is performed.

## Roadmap
- [ ] Stable public API and versioned schemas
- [ ] More unit, integration and adversarial tests
- [ ] Reproducible benchmarks and sample datasets
- [ ] Signed releases and dependency review
- [ ] Documentation and contribution guide

## License
MIT. See [LICENSE](LICENSE).
