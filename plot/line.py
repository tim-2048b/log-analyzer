from util.load_csv import load_csv_df
from util.const import Num_str_value


import pandas as pd
from matplotlib import pyplot as plt


def plot_line_from_log(
    log_path: str,
    x_metric: str,
    y_metric: str,
    *,
    df: pd.DataFrame | None = None,
    x_label: str | None = None,
    y_label: str | None = None,
    strip_log_whitespace: bool = True,
    exclude_pattern: dict[str, Num_str_value | list[Num_str_value]] = {},
    include_pattern: dict[str, Num_str_value | list[Num_str_value]] = {},
    max_rows = 1000,
    figsize: tuple = (12,16),
    title: str = "Default title for line",
    sep: str = ",",
):
    # Load your Windows Event CSV     
    if df is None:
        df = load_csv_df(
            path= log_path ,
            exclude_pattern= exclude_pattern ,
            encoding= "utf-16",
            sep=sep,
            strip_whitespace= strip_log_whitespace
        )

    
    # Plotting Event IDs over Time
    fig, ax = plt.subplots(figsize=(12, 20))

    if x_label is None:
        x_label = f"{x_metric} main line"

    if y_label is None:
        y_label = f"{y_metric} main line"

    ax.set_xlabel(x_label)
    ax.set_ylabel(y_label)
    ax.set_title('Windows Event ID Timeline')

    # TODO debug purpose, remove after test pass
    print(df["Level"].unique())
    
    
   

    ax.plot(df[x_metric][0:max_rows], df[y_metric][0:max_rows], alpha=0.4)




    plt.xticks(rotation=45)
    # plt.savefig("output.png", dpi=150, bbox_inches="tight")

    plt.tight_layout()
    plt.show()