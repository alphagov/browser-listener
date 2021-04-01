.SHELL := /bin/bash
.DEFAULT_GOAL := test

deploy:
	cf7 push --strategy rolling

test:
	echo "Do test"
