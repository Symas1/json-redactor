_default:
	- $(MAKE) sync; $(MAKE) lint; $(MAKE) mypy

help:
	json-redactor --help

_JSON = '[{ "name": "Anna", "email": "anna@example.com", "ssn": "123-45-6789" }, { "name": "Ben",  "email": "ben@example.com",  "ssn": "987-65-4321" }]'

examples:
	cat assets/people.json | json-redactor --keys email,ssn --hash > assets/output.json
	@echo "\n"
	echo $(_JSON) | json-redactor --keys email,ssn --hash
	@echo "\n"
	echo $(_JSON) | json-redactor --keys email --keys-regex ^ss
	@echo "\n"
	echo $(_JSON) | json-redactor --keys ssn --key-file assets/keys
	@echo "\n"

sync:
	uv sync --all-groups --all-packages --all-extras

lint:
	uv run ruff check src tests

mypy:
	uv run mypy src tests

test:
	uv run pytest tests
