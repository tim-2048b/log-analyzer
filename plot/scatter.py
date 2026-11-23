from matplotlib import pyplot as plt
import pandas as pd
from util.const import Num_str_value
from util.load_csv import load_csv_df




def plot_scatter_from_log(
    log_path: str,
    x_metric: str,
    y_metric: str,
    x_label: str | None = None,
    y_label: str | None = None,
    columns: list[str] | None = None, 
    df: pd.DataFrame | None = None,
    exclude_pattern: dict[str, Num_str_value | list[Num_str_value]] = {},
    include_pattern: dict[str, Num_str_value | list[Num_str_value]] = {},
    figsize: tuple = (12,16),
    max_rows = 1000,
    sep: str = ",",
    title: str = "Default title for scatter",  
):
    # Load your CSV or TSV file here     
    if df is None:
        df = load_csv_df(
            path=  log_path , 
            columns= columns,
            exclude_pattern= exclude_pattern , 
            encoding= "utf-16", 
            sep=sep,
            strip_whitespace= True,
            include_pattern= include_pattern,
            max_rows= max_rows
        )

   

    # TODO the y_metric need to be string?
    # df['EventID'] = df['EventID'].astype(str)  # Ensure Event ID is treated as a string for plotting

    

    scatters = {}

    # Default label come from 
    if x_label is None:
        x_label = f"{x_metric} main line"
    
    if y_label is None:
        y_label = f"{y_metric} main line"
    fig, ax = plt.subplots( figsize= figsize )
    # Add select legend with interactive functionality
    legend = ax.legend(loc='upper left', title="Click legend to toggle")

    print(df["Level"].unique())
    
    # Draw Scatter by group
    for value, group in df.groupby(y_metric):
        sc = ax.scatter(group[x_metric], [str(value)] * len(group), label=f'{y_metric} {value}', alpha=0.7)
        scatters[sc] = group
        ax.scatter(df[x_metric], df[y_metric], alpha=0.4, 
            edgecolors='none',
            picker=True
        )


    ax.set_xlabel(x_label) 
    ax.set_ylabel(y_label)
    ax.set_title(title)

    # Create a dictionary mapping legend lines to the actual scatter plots
    legend_to_scatter = {}
    for legend_text, scatter_plot in zip(legend.get_texts(), scatters.keys()):
        legend_text.set_picker(True) # Enable picking on legend text
        legend_to_scatter[legend_text] = scatter_plot

    
    

    # Define the click behavior inline function
    def on_pick(event):
        legend_text = event.artist
        if legend_text in legend_to_scatter:
            scatter_plot = legend_to_scatter[legend_text]
            # Toggle visibility
            visible = not scatter_plot.get_visible()
            scatter_plot.set_visible(visible)
            # Change legend text alpha to show it's disabled
            legend_text.set_alpha(1.0 if visible else 0.2)
            fig.canvas.draw()

    # Attach pick event to canvas
    fig.canvas.mpl_connect('pick_event', on_pick)


    plt.xticks(rotation=45)
    plt.savefig("output.png", dpi=150, bbox_inches="tight")

    plt.tight_layout()
    plt.show()



