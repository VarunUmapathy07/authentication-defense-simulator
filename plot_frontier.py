"""
Plot security vs usability tradeoff from summary_aggregated.csv
"""
import os
import csv
import sys

try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("matplotlib not installed")
    print("Install it with: pip install matplotlib")
    sys.exit(1)


def load_aggregated_results(results_dir):
    """Load summary_aggregated.csv"""
    agg_file = os.path.join(results_dir, "summary_aggregated.csv")
    
    if not os.path.exists(agg_file):
        print(f"Error: {agg_file} not found!")
        print("Run analyze_sweep.py first")
        return []
    
    results = []
    with open(agg_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            results.append({
                'defense': row['defense'],
                'param_value': row['param_value'],
                'mean_compromise': float(row['mean_compromise_rate']),
                'std_compromise': float(row['std_compromise_rate']),
                'mean_block': float(row['mean_block_rate']),
                'std_block': float(row['std_block_rate'])
            })
    
    return results


def plot_frontier(results, output_dir):
    """Create frontier plot with error bars"""
    
    # Group by defense
    defenses = {}
    for r in results:
        if r['defense'] not in defenses:
            defenses[r['defense']] = []
        defenses[r['defense']].append(r)
    
    # Use matplotlib default colors
    colors = ['C0', 'C1', 'C2', 'C3', 'C4']
    
    plt.figure(figsize=(12, 8))
    
    # Plot each defense
    label_offset = 0
    for i, (defense_name, points) in enumerate(defenses.items()):
        color = colors[i % len(colors)]
        
        # Find best point (lowest compromise) for this defense to label
        best_point = min(points, key=lambda p: (p['mean_compromise'], p['mean_block']))        
        for point in points:
            x = point['mean_block']
            y = point['mean_compromise']
            xerr = point['std_block']
            yerr = point['std_compromise']
            
            # Plot point with error bars
            print(defense_name, point['param_value'], "x=", x, "y=", y)
            plt.errorbar(x, y, xerr=xerr, yerr=yerr, 
                        fmt='o', color=color, markersize=10,
                        capsize=5, alpha=0.7, label=None)
            
            # Only label the best point per defense to avoid overlap
            if point == best_point:
                # Offset labels vertically to avoid overlap
                offset_y = 10 + (label_offset * 25)
                plt.annotate(f"{defense_name}\n{point['param_value']}", (x, y), 
                            xytext=(15, offset_y), textcoords='offset points',
                            fontsize=9, alpha=0.8, color=color)
                label_offset += 1
    
    # Create legend
    legend_elements = [mpatches.Patch(color=colors[i % len(colors)], label=d) 
                      for i, d in enumerate(defenses.keys())]
    plt.legend(handles=legend_elements, loc='upper right', fontsize=10)
    
    # Labels and title
    plt.xlabel('User Block Rate (higher = worse usability)', fontsize=12)
    plt.ylabel('Victim Compromise Rate (higher = worse security)', fontsize=12)
    plt.title('Security vs Usability Frontier\n(lower-left is better)', fontsize=14, fontweight='bold')
    
    # Clamp axes to 0 (compromise/block rates can't be negative)
    plt.xlim(0, 1.0)   # 0 to 100%
    plt.ylim(0, 0.025)  # 0 to 25%



    
    # Grid
    plt.grid(True, alpha=0.3)
    
    # Reference lines for ideal (0,0)
    plt.axhline(y=0, color='green', linestyle='--', alpha=0.3, linewidth=1)
    plt.axvline(x=0, color='green', linestyle='--', alpha=0.3, linewidth=1)
    
    plt.tight_layout()
    
    # Save
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, 'frontier.png')
    plt.savefig(output_file, dpi=150)
    print(f"Saved: {output_file}")
    plt.close()


def main():
    if len(sys.argv) > 1:
        results_dir = sys.argv[1]
    else:
        results_dir = "results"
    
    print(f"Loading results from {results_dir}/")
    results = load_aggregated_results(results_dir)
    
    if not results:
        print("No results found!")
        return
    
    print(f"Found {len(results)} data points")
    
    # Create figures directory
    figures_dir = os.path.join(results_dir, "figures")
    
    print("Creating frontier plot...")
    plot_frontier(results, figures_dir)
    
    print(f"\nPlot saved to: {figures_dir}/frontier.png")


if __name__ == "__main__":
    main()