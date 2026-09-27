# TRIGLYPH — сборки нет, только проверки и запуск
PY ?= python3

.PHONY: help test selftest bench demo lint clean install

help:
	@echo "make test      — 116 тестов (unittest)"
	@echo "make selftest  — 32 проверки по официальным тест-векторам"
	@echo "make bench     — скорость на этой машине"
	@echo "make demo      — веб-демо на http://0.0.0.0:8000"
	@echo "make install   — pip install -e . (появится команда triglyph)"

test:
	$(PY) -m unittest discover -s tests -v

selftest:
	$(PY) -m triglyph selftest -v

bench:
	$(PY) -m triglyph bench

demo:
	$(PY) web/server.py

install:
	$(PY) -m pip install -e .

lint:
	$(PY) -m compileall -q triglyph tests web && echo "syntax OK"

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
