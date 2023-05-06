ipft:
	@./scripts/make.sh ipft

clean:
	@./scripts/make.sh clean

format:
	@./scripts/make.sh format

format-check: format
	@./scripts/format.sh check_diff

docs: src/ipft
	@./scripts/docs.sh build

docs-check: docs
	@./scripts/docs.sh check_diff
