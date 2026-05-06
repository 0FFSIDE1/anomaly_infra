.PHONY: clean build tag release bump

clean:
	rm -rf build dist *.egg-info

build: clean
	python -m build

tag:
	git tag v$(VERSION)
	git push origin v$(VERSION)

release:
	make tag VERSION=$(VERSION)

bump:
	sed -i 's/^version = ".*"/version = "$(VERSION)"/' pyproject.toml