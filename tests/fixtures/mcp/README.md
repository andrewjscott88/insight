# MCP protocol schema fixture

The unmodified official 2026-07-28 JSON schema is used only for offline protocol tests.
Fetched on 2026-11-22 from
https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2026-07-28/schema.json
with Git blob SHA `b73fe650e95953edc36f6ca191d4beba22d54022` and file SHA-256
`92eda8a5099cd38a50c734699988426bb4583a7f1f9d8f8ff8b7fa71834e9b6e`.

The upstream licensing transition notice, Apache-2.0 terms and retained MIT terms are in
[LICENSE](LICENSE), copied from the upstream repository. No upstream NOTICE file was present.
The schema is a test fixture, not an installed dependency. Validation uses the existing
`jsonschema` development dependency and never downloads a schema or reference.
