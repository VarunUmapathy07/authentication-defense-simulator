# Getting Started

## Install

```bash
pip install -r requirements.txt
```

## Run everything

```bash
make reproduce
```

Or use the shell script:
```bash
./run_all.sh
```

This runs the parameter sweep, analyzes the results, and generates the security–usability frontier plot.

## Run tests

```bash
make test
```

Or:
```bash
python3 tests/test_defenses.py
```

## What you get

After running, check:

- `results/summary.csv` - All trials with full metrics
- `results/summary_aggregated.csv` - Mean +/- std for each config  
- `results/figures/frontier.png` - Security vs usability plot

## Quick test

To run faster, edit `sweep.py` and change:

```python
run_sweep(output_base="results", seeds=1, duration=1800)
```

Then run `make reproduce`.

## Manual steps (if make doesn't work)

```bash
python3 sweep.py
python3 analyze_sweep.py results
python3 plot_frontier.py results
```

## Troubleshooting

**make: command not found**  
Use `./run_all.sh` or run the 3 python commands manually

**Takes too long**  
Edit `sweep.py` and reduce `seeds` or `duration`

**Tests fail**  
Make sure you're in the project directory

**No plots**  
Install matplotlib: `pip install matplotlib`
