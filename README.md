# json-redactor
Redacts or hashes sensitive data inside an arbitrarily nested JSON document

## Usage
Prerequisites: `uv` and `uvx`.

```sh
uvx --from git+https://github.com/Symas1/json-redactor@v1.0.0 json-redactor --help
```

Review usage examples in `Makefile.examples` target.

## Contributing
Prerequisites: `uv`, `make` and (optional) `direnv`.

```sh
make sync && source .venv/bin/activate

make lint mypy test

make help
```
