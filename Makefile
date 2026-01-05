VENV := .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip

.PHONY: reproduce test clean venv

venv:
	python3 -m venv $(VENV)
	$(PIP) install -r requirements.txt

reproduce: venv
	@echo "Running full pipeline..."
	$(PY) sweep.py
	$(PY) analyze_sweep.py results
	$(PY) plot_frontier.py results
	@echo ""
	@echo "Results saved to:"
	@echo "  results/summary.csv"
	@echo "  results/summary_aggregated.csv"
	@echo "  results/figures/frontier.png"

test: venv
	$(PY) tests/test_defenses.py

clean:
	rm -rf results/ __pycache__ tests/__pycache__ $(VENV)
