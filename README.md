# json-redactor
Redacts or hashes sensitive data inside an arbitrarily nested JSON document

## Usage
Prerequisites: `uv` and `uvx`.

```sh
uvx --from git+https://github.com/Symas1/json-redactor@v2.0.1 json-redactor --help

echo '[{ "name": "Anna", "email": "anna@example.com", "ssn": "123-45-6789" }, { "name": "Ben",  "email": "ben@example.com",  "ssn": "987-65-4321" }]' \
  | uvx --from git+https://github.com/Symas1/json-redactor@v2.0.1 json-redactor --keys email --keys-regex ^ss --hash
```

Review usage examples in `Makefile.examples` target.

## Contributing
Prerequisites: `uv`, `make` and (optional) `direnv`.

```sh
make sync && source .venv/bin/activate

make lint mypy test

make help
```
