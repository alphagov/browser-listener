.SHELL := /bin/bash
.DEFAULT_GOAL := test

deploy:
	cf7 push --strategy rolling

test:
	python -m doctest *.py
	python -m pytest
