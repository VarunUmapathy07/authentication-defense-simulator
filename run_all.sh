#!/bin/bash

echo "=========================================="

echo "Full Reproducibility Pipeline"
echo "=========================================="
echo ""

# Run sweep
echo "Step 1: Running parameter sweep..."
python3 sweep.py
if [ $? -ne 0 ]; then
    echo "Error running sweep"
    exit 1
fi
echo ""

# Analyze
echo "Step 2: Analyzing results..."
python3 analyze_sweep.py results
if [ $? -ne 0 ]; then
    echo "Error analyzing results"
    exit 1
fi
echo ""

# Plot
echo "Step 3: Generating frontier plot..."
python3 plot_frontier.py results
if [ $? -ne 0 ]; then
    echo "Error generating plot"
    exit 1
fi
echo ""

echo "=========================================="
echo "COMPLETE!"
echo "=========================================="
echo ""
echo "Results:"
echo "  results/summary.csv - Per-trial results"
echo "  results/summary_aggregated.csv - Aggregated with error bars"
echo "  results/figures/frontier.png - Security vs usability frontier"
echo ""
