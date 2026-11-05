# hermes-hackathon-plugin

Starter scaffold for the [Hermes Agent Plugin Hackathon](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins).

> **Status:** scaffolding only. Plugin concept and implementation TBD.

## What it does (placeholder)

Registers a single `ping` tool that returns a greeting. Replace with the real
plugin before submission.

## Install (local dev)

```bash
# Clone and bootstrap a replicable dev environment
git clone https://github.com/309nahe/hermes-hackathon-plugin
cd hermes-hackathon-plugin
./scripts/bootstrap.sh
```

## Develop

```bash
make validate   # runs `hermes plugins validate . --install-deps`
make test       # runs pytest
make enable     # enables the plugin in ~/.hermes/config.yaml
```

## Disclosure (catalog rule 13)

Fill in before submission:

- Network calls: none yet
- Shell commands: none yet
- Background processes: none yet
- Stored credentials: none yet
- Telemetry: none (opt-in only)

## Rename before submission

1. Update `name` in `plugin.yaml` and the repo name.
2. Update `provides_tools` / `provides_hooks` to match what `register()` registers.
3. Set `requires_hermes` to a real floor (never newer than the current release).
4. Run `hermes plugins validate . --install-deps` until green.
5. Pin a full 40-char SHA in `plugin-catalog/<name>.yaml`.

## License

MIT
