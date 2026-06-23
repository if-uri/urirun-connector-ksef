.PHONY: help manifest bindings smoke test
help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n",$$1,$$2}'
manifest: ## Print the connector manifest
	urirun-connector-ksef manifest
bindings: ## Print urirun bindings
	urirun-connector-ksef bindings
smoke: ## bindings validate + auth dry-run plan (no network, no credentials)
	urirun-connector-ksef bindings | urirun validate -
	urirun-connector-ksef authenticate --env test --nip 1234567890
test: ## Install editable + pytest + smoke
	pip install -e ".[test]" && python3 -m pytest -q && $(MAKE) smoke
