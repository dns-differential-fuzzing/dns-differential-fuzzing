# ---
# jupyter:
#   jupytext:
#     formats: ipynb,py:percent
#     notebook_metadata_filter: -jupytext.text_representation.jupytext_version
#     text_representation:
#       extension: .py
#       format_name: percent
#       format_version: '1.3'
#   kernelspec:
#     display_name: Python 3 (ipykernel)
#     language: python
#     name: python3
# ---

# %%
# %matplotlib inline
# # %matplotlib widget

import dataclasses

# %%
import functools
import json
import os
import os.path
from collections.abc import Callable
from glob import glob
from typing import Any

import common_functions
import ipywidgets as widgets
import matplotlib.axes

# import mplcursors
import matplotlib.pyplot as plt
from IPython.display import display
from matplotlib.ticker import FuncFormatter, MultipleLocator, PercentFormatter

common_functions.matplotlib_better_lines()
plt.rcParams["savefig.bbox"] = "tight"
plt.rcParams["figure.autolayout"] = True

Stats = list[dict[str, Any]]

# %%
callbacks: list[Any] = []
latest_stats: tuple[str, Stats] | None = None


def find_available_stats() -> None:
    options = []

    fuzzing_runs = sorted(glob("/mnt/data/Downloads/dnsdiff/20??-??-?? *"))
    for fr in fuzzing_runs:
        statsfiles = sorted(glob(os.path.join(fr, "stats", "*")))
        if len(statsfiles) == 0:
            continue
        with open(statsfiles[-1]) as f:
            endtime = json.load(f)["start_time"]["secs"]
            hours = endtime // 3600
            minutes = endtime % 3600 // 60
            pretty_time = f"{hours:>2}:{minutes:0>2}"
        options.append(
            (
                f"{os.path.basename(fr)} (Samples: {len(statsfiles)}, Time: {pretty_time}h)",
                fr,
            )
        )

    output = widgets.Output()
    dd = widgets.Dropdown(
        options=options,
        value=fuzzing_runs[-1],
        description="Fuzzing Run:",
        disabled=False,
        layout={"width": "max-content"},
    )

    def observer(change: dict[Any, Any]) -> None:
        global latest_stats
        with output:
            basepath = change["new"]
            name = os.path.basename(basepath)
            statsfiles = glob(os.path.join(basepath, "stats", "*"))
            stats = [json.load(open(sf)) for sf in sorted(statsfiles)]
            latest_stats = (name, stats)
            for cb in callbacks:
                cb(name, stats)

    # The `names` doesn't type check since it inferes to the wrong type
    dd.observe(observer, names="value")  # type: ignore

    display(dd, output)


def register_cb(f: Callable[[Stats], None]) -> None:
    global latest_stats
    output = widgets.Output()

    def replot(name: str, stats: Stats, op: widgets.Output) -> None:
        op.clear_output()
        with op:
            print(f"Plotting {name}")
            f(stats)

    cb = functools.partial(replot, op=output)
    callbacks.append(cb)
    with output:
        print("Registered callback")
        if latest_stats:
            cb(latest_stats[0], latest_stats[1])

    display(output)


find_available_stats()


# %% [markdown]
# # Coverage Plot Layout
#
# x-axis: Time based on `start_time` value
#
# y-axis (left): % of edges covered, i.e., `explored_edges / edges * 100`
#     Scale linear from 0 to x%. Probably low x values.
# y-axis (right): Number of cases which increase coverage, i.e., `progress_fuzz_case_count`
#     Scale linear from 0


# %%
def fmt_time_axis(axis: Any, ts_max: float, nmarks: int = 4) -> None:
    def float_duration_fmt_func(x: float, _pos: int) -> str:
        hours = int(x // 3600)
        minutes = int((x % 3600) // 60)
        # seconds = int(x % 60)

        return f"{hours:d}:{minutes:02d}"
        # return "{:d}:{:02d}:{:02d}".format(hours, minutes, seconds)

    float_duration_fmt = FuncFormatter(float_duration_fmt_func)

    # We can fit 4 numbers onto the axis.
    # Check which base value we can reasonably use for that
    # There is always the label for 0, so only n-1 other labels
    # We want roughly 4 labels in total.
    # Try different "units" until we find something that works

    minor_unit: int = 3600
    major_unit: int = round(ts_max / minor_unit / (nmarks - 1)) * minor_unit
    if major_unit == 0:
        minor_unit = 900
        major_unit = round(ts_max / minor_unit / (nmarks - 1)) * minor_unit
    if major_unit == 0:
        minor_unit = 60
        major_unit = round(ts_max / minor_unit / (nmarks - 1)) * minor_unit
    if major_unit == 0:
        major_unit = 1
        minor_unit = 0

    # Delete the minor_unit if they are at the same places as the major units
    if minor_unit == major_unit:
        minor_unit = 0

    print(f"{ts_max=} {major_unit=}")
    axis.set_major_formatter(float_duration_fmt)
    axis.set_major_locator(MultipleLocator(base=major_unit))
    if minor_unit != 0:
        axis.set_minor_locator(MultipleLocator(base=minor_unit))


# %%
def coverage_plots(stats: Stats) -> None:
    plt.rcParams["figure.figsize"] = [8.5, 5]

    # shared x-axis
    timestamps: list[float] = []
    # per resolver gather edge coverage percentage
    edge_coverage_percentage: dict[str, list[float]] = {}

    for stat in stats:
        # There is no nanosecond option for timedelta
        ts = stat["start_time"]["secs"] + stat["start_time"]["nanos"] / 1_000_000_000
        timestamps.append(ts)

        for resolver, rstats in stat["coverage"].items():
            edge_coverage_percentage.setdefault(resolver, []).append(
                rstats["explored_edges"] / rstats["edges"] * 100
            )

    for resolver, ecp in edge_coverage_percentage.items():
        # Add a fake entry point for time 0 with 0 coverage
        plt.plot([0] + timestamps, [0] + ecp, label=resolver)

    ax = plt.gca()
    ax.yaxis.set_major_formatter(PercentFormatter())

    # Format time axis
    ts_max = max(timestamps)
    fmt_time_axis(ax.xaxis, ts_max)

    plt.legend(
        loc="center left",
        bbox_to_anchor=(1.0, 0.5),
    )

    plt.title("Edge Coverage")
    plt.xlabel("Time in HH:MM")
    plt.ylabel("Edge Coverage")
    plt.xlim(left=0)
    plt.ylim(bottom=0)
    plt.savefig("fuzz-edge-coverage-over-time.svg")
    plt.show()


register_cb(coverage_plots)

# %%
RESOLVER_PRETTY = {
    "bind9": "BIND9",
    "bind9_11": "BIND9\nv9.11",
    "knot-resolver": "Knot\nResolver",
    "maradns": "Deadwood",
    "pdns-recursor": "PowerDNS\nRecursor",
    "resolved": "resolved",
    "trust-dns": "trust-dns",
    "unbound": "Unbound",
}


# %%
def coverage_progress_plots(stats: Stats) -> None:
    plt.rcParams["figure.figsize"] = [8.5, 3.5]

    # shared x-axis
    timestamps: list[float] = []
    # per resolver gather the fuzz case count
    coverage_progress_count: dict[str, list[int]] = {}

    for stat in stats:
        # There is no nanosecond option for timedelta
        ts = stat["start_time"]["secs"] + stat["start_time"]["nanos"] / 1_000_000_000
        timestamps.append(ts)

        for resolver, rstats in stat["coverage"].items():
            coverage_progress_count.setdefault(resolver, []).append(
                rstats["progress_fuzz_case_count"]
            )

    for resolver, cpc in coverage_progress_count.items():
        resolver = RESOLVER_PRETTY[resolver]
        # Add a fake entry point for time 0 with 0 coverage
        plt.plot([0] + timestamps, [0] + cpc, label=resolver)

    ax = plt.gca()

    # Format time axis
    ts_max = max(timestamps)
    fmt_time_axis(ax.xaxis, ts_max)

    plt.legend(
        loc="center left",
        bbox_to_anchor=(1.0, 0.5),
    )

    plt.title("Edge Coverage Progress Cases")
    plt.xlabel("Time in HH:MM")
    plt.ylabel("Inputs uncovering new edge coverage")
    plt.xlim(left=0)
    plt.ylim(bottom=0)
    plt.savefig("fuzz-coverage-progress-over-time.svg")
    plt.show()


register_cb(coverage_progress_plots)


# %%
def coverage_vs_cases_plot(stats: Stats) -> None:
    plt.rcParams["figure.figsize"] = [7, 5]

    # per resolver gather edge coverage percentage
    edge_coverage_percentage_vs_coverage_progress: dict[
        str, tuple[list[float], list[int]]
    ] = {}

    for stat in stats:
        for resolver, rstats in stat["coverage"].items():
            edge_coverage_percentage_vs_coverage_progress.setdefault(
                resolver, ([], [])
            )[0].append(rstats["explored_edges"] / rstats["edges"] * 100)
            edge_coverage_percentage_vs_coverage_progress.setdefault(
                resolver, ([], [])
            )[1].append(rstats["progress_fuzz_case_count"])

    for resolver, (ecp, cpc) in edge_coverage_percentage_vs_coverage_progress.items():
        # Add a fake entry point for time 0 with 0 coverage
        plt.plot([0] + cpc, [0] + ecp, label=resolver)

    ax = plt.gca()
    # ax.xaxis.set_major_formatter(float_duration_fmt)
    ax.yaxis.set_major_formatter(PercentFormatter())
    plt.legend()

    plt.title("Edge Coverage Progress Cases")
    plt.xlabel("Fuzz Cases progressing edge coverage")
    plt.ylabel("Edge Coverage")
    plt.xlim(left=0)
    plt.ylim(bottom=0)
    plt.savefig("fuzz-coverage-vs-cases.svg")
    plt.show()


register_cb(coverage_vs_cases_plot)


# %%
def differences_plot(stats: Stats, keys: list[str], title: str) -> None:
    plt.rcParams["figure.figsize"] = [15, 10]

    # shared x-axis
    timestamps: list[float] = []
    # per resolver pair, per resolution, count
    differences: dict[tuple[str, str], dict[str, list[int]]] = {}

    for stat in stats:
        # There is no nanosecond option for timedelta
        ts = stat["start_time"]["secs"] + stat["start_time"]["nanos"] / 1_000_000_000
        timestamps.append(ts)

        for resolvers, dstats in stat["differences"]:
            per_resolvers = differences.setdefault((resolvers[0], resolvers[1]), {})

            for key in keys:
                per_resolvers.setdefault(key, []).append(dstats[key])

    all_resolvers: list[str] = sorted({r for rs in differences for r in rs})

    fig = plt.gcf()
    gs = fig.add_gridspec(
        # -1 because we don't need space for the diagonal
        nrows=len(all_resolvers) - 1,
        ncols=len(all_resolvers) - 1,
        hspace=0,
        wspace=0,
    )
    axes = gs.subplots(
        sharex=True,
        sharey=True,
    )
    # Axes is not an array if the dimensions are 1 by 1
    if type(axes) == matplotlib.axes.Axes:
        axes = [[axes]]

    for resolvers, resolvers_diff_counts in differences.items():
        idx1 = all_resolvers.index(resolvers[0])
        idx2 = all_resolvers.index(resolvers[1])
        # The invariant is that idx1 < idx2
        # Therefore we need to substract 1 from idx2, since we decreased the grid size
        ax = axes[idx2 - 1][idx1]

        for diff_key, diff_count in resolvers_diff_counts.items():
            ax.plot(
                [0] + timestamps,
                [0] + diff_count,
                label=diff_key,
                markevery=0.25,
            )

    # Set limits. All axes are shared, setting once is enough
    axes[0][0].set_xlim(left=0)
    axes[0][0].set_ylim(bottom=0)
    # Format time axis
    ts_max = max(timestamps)
    fmt_time_axis(axes[0][0].xaxis, ts_max)

    # Set a label for each row/column
    for idx, res in enumerate(all_resolvers):
        if idx > 0:
            # Move the alignment of the tick labels, such that they don't overlap
            # The first tick label gets moved right, and the last ones left
            # That ensures that at neighboring plot they don't overlap
            ticklabels = axes[-1][idx - 1].get_xticklabels()
            # set the alignment for outer ticklabels
            ticklabels[0].set_ha("left")
            ticklabels[1].set_ha("left")
            ticklabels[-2].set_ha("right")
            ticklabels[-1].set_ha("right")

            axes[idx - 1][0].set_ylabel(res)
        if idx < len(all_resolvers) - 1:
            axes[-1][idx].set_xlabel(res)

    for idx_out, ax_outer in enumerate(axes):
        for idx, ax in enumerate(ax_outer):
            # Hide x labels and tick labels for all but outer plots.
            ax.label_outer()
            ax.tick_params(
                # x, y, both
                axis="both",
                # major, minor, both
                which="both",
                # in, out, inout
                direction="inout",
            )
            if idx_out < idx:
                ax.axis("off")

    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        # The upper right hand corner of the legend
        loc="upper right",
        # must be places on the right hand (1.0) upper (1.0) corner
        bbox_to_anchor=(1.0, 1.0),
        # of the specified axes. [0][-1] picks the upper right hand subfigure
        bbox_transform=axes[0][-1].transAxes,
    )

    fig.supxlabel("Runtime in HH:MM")
    fig.supylabel("Resolver comparisons")
    fig.suptitle(title)
    slug = title.replace(" ", "-").lower()
    plt.savefig(f"fuzz-resolver-comparisons-{slug}.svg")
    plt.show()


register_cb(
    lambda stats: differences_plot(
        stats,
        keys=[
            # "no_diff",
            "insignificant",
            "significant",
            "total",
        ],
        title="Fuzzing Output Comparisons",
    )
)
register_cb(
    lambda stats: differences_plot(
        stats,
        keys=[
            # "repro_no_diff",
            "repro_insignificant",
            "repro_significant_other",
            # "repro_significant",
        ],
        title="Reproductions Failures",
    )
)


# %%
def difference_kinds_plot(stats: Stats) -> None:
    plt.rcParams["figure.figsize"] = [15, 10]

    # Gather a list of all the diffkinds
    # Checking the last timestamp should be enough, since this list can only every increment
    all_diffkinds: set[str] = {
        key
        for dstats in stats[-1]["differences"]
        for key in dstats[1]["per_diff_kind"].keys()
    }

    # shared x-axis
    timestamps: list[float] = []
    # per resolver pair, per resolution, count
    differences: dict[tuple[str, str], dict[str, list[int]]] = {}

    for idx, stat in enumerate(stats):
        # There is no nanosecond option for timedelta
        ts = stat["start_time"]["secs"] + stat["start_time"]["nanos"] / 1_000_000_000
        timestamps.append(ts)

        for resolvers, dstats in stat["differences"]:
            per_resolvers = differences.setdefault((resolvers[0], resolvers[1]), {})
            total = dstats["total"]
            dstats = dstats["per_diff_kind"]

            for key in all_diffkinds:
                # Some keys might not exist or not exist for all timestamps
                per_resolver_stats = per_resolvers.setdefault(key, [])
                per_resolver_stats.append(dstats.get(key, 0))

            per_resolver_stats = per_resolvers.setdefault("total", [])
            per_resolver_stats.append(total)

    all_resolvers: list[str] = sorted({r for rs in differences for r in rs})

    fig = plt.gcf()
    gs = fig.add_gridspec(
        # -1 because we don't need space for the diagonal
        nrows=len(all_resolvers) - 1,
        ncols=len(all_resolvers) - 1,
        hspace=0,
        wspace=0,
    )
    axes = gs.subplots(
        sharex=True,
        sharey=True,
    )
    # Axes is not an array if the dimensions are 1 by 1
    if type(axes) == matplotlib.axes.Axes:
        axes = [[axes]]

    for resolvers, resolvers_diff_counts in differences.items():
        idx1 = all_resolvers.index(resolvers[0])
        idx2 = all_resolvers.index(resolvers[1])
        # The invariant is that idx1 < idx2
        # Therefore we need to substract 1 from idx2, since we decreased the grid size
        ax = axes[idx2 - 1][idx1]

        idx_max = len(resolvers_diff_counts)
        for idx, (diff_key, diff_count) in enumerate(resolvers_diff_counts.items()):
            if max(diff_count) > 0:
                if diff_key == "total":
                    # print([0] + timestamps)
                    # print([0] + diff_count)
                    ax.plot(
                        [0] + timestamps,
                        [0] + diff_count,
                        markevery=None,
                        color="black",
                        alpha=0.5,
                        marker="",
                        linestyle="solid",
                    )
                else:
                    ax.plot(
                        [0] + timestamps,
                        [0] + diff_count,
                        label=diff_key,
                        markevery=((idx / idx_max) * 0.25, 0.25),
                    )
            else:
                # Plot outside the drawing range but preserve that each key is plotted for each subplot
                # This preserves the correct color order between them
                ax.plot([-1000], [-1000], label=diff_key)

    # Set limits. All axes are shared, setting once is enough
    axes[0][0].set_xlim(left=0)
    axes[0][0].set_ylim(bottom=0)
    # Format time axis
    ts_max = max(timestamps)
    fmt_time_axis(axes[0][0].xaxis, ts_max)

    # Set a label for each row/column
    for idx, res in enumerate(all_resolvers):
        if idx > 0:
            # Move the alignment of the tick labels, such that they don't overlap
            # The first tick label gets moved right, and the last ones left
            # That ensures that at neighboring plot they don't overlap
            ticklabels = axes[-1][idx - 1].get_xticklabels()
            # set the alignment for outer ticklabels
            ticklabels[0].set_ha("left")
            ticklabels[1].set_ha("left")
            ticklabels[-2].set_ha("right")
            ticklabels[-1].set_ha("right")

            axes[idx - 1][0].set_ylabel(res)
        if idx < len(all_resolvers) - 1:
            axes[-1][idx].set_xlabel(res)

    for idx_out, ax_outer in enumerate(axes):
        for idx, ax in enumerate(ax_outer):
            # Hide x labels and tick labels for all but outer plots.
            ax.label_outer()
            ax.tick_params(
                # x, y, both
                axis="both",
                # major, minor, both
                which="both",
                # in, out, inout
                direction="inout",
            )
            if idx_out < idx:
                ax.axis("off")

    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        ncols=2,
        # The upper right hand corner of the legend
        loc="upper right",
        # must be places on the right hand (1.0) upper (1.0) corner
        bbox_to_anchor=(1.0, 1.0),
        # of the specified axes. [0][-1] picks the upper right hand subfigure
        bbox_transform=axes[0][-1].transAxes,
    )

    fig.supxlabel("Runtime in HH:MM")
    fig.supylabel("Occurence of Difference in Resolver Comparisons")
    fig.suptitle("Difference Kinds")
    plt.savefig("fuzz-resolver-comparisons-diff-kinds.svg")
    plt.show()


register_cb(difference_kinds_plot)


# %%
def difference_category_plot(stats: Stats) -> None:
    plt.rcParams["figure.figsize"] = [10, 7]

    # Gather a list of all the diffkinds
    # Checking the last timestamp should be enough, since this list can only every increment
    all_diffkinds: set[str] = {
        key
        for dstats in stats[-1]["differences"]
        for key in dstats[1]["per_diff_category"].keys()
    }

    # shared x-axis
    timestamps: list[float] = []
    # per resolver pair, per resolution, count
    differences: dict[tuple[str, str], dict[str, list[int]]] = {}

    for idx, stat in enumerate(stats):
        # There is no nanosecond option for timedelta
        ts = stat["start_time"]["secs"] + stat["start_time"]["nanos"] / 1_000_000_000
        timestamps.append(ts)

        for resolvers, dstats in stat["differences"]:
            per_resolvers = differences.setdefault((resolvers[0], resolvers[1]), {})
            total = dstats["total"]
            dstats = dstats["per_diff_category"]

            for key in all_diffkinds:
                # Some keys might not exist or not exist for all timestamps
                per_resolver_stats = per_resolvers.setdefault(key, [])
                per_resolver_stats.append(dstats.get(key, 0))

            per_resolver_stats = per_resolvers.setdefault("total", [])
            per_resolver_stats.append(total)

    all_resolvers: list[str] = sorted({r for rs in differences for r in rs})

    fig = plt.gcf()
    gs = fig.add_gridspec(
        # -1 because we don't need space for the diagonal
        nrows=len(all_resolvers) - 1,
        ncols=len(all_resolvers) - 1,
        hspace=0,
        wspace=0,
    )
    axes = gs.subplots(
        sharex=True,
        sharey=True,
    )
    # Axes is not an array if the dimensions are 1 by 1
    if type(axes) == matplotlib.axes.Axes:
        axes = [[axes]]

    for resolvers, resolvers_diff_counts in differences.items():
        idx1 = all_resolvers.index(resolvers[0])
        idx2 = all_resolvers.index(resolvers[1])
        # The invariant is that idx1 < idx2
        # Therefore we need to substract 1 from idx2, since we decreased the grid size
        ax = axes[idx2 - 1][idx1]

        idx_max = len(resolvers_diff_counts)
        for idx, (diff_key, diff_count) in enumerate(resolvers_diff_counts.items()):
            if max(diff_count) > 0:
                if diff_key == "total":
                    ax.plot(
                        [0] + timestamps,
                        [0] + diff_count,
                        markevery=None,
                        color="black",
                        alpha=0.5,
                        marker="",
                        linestyle="solid",
                    )
                else:
                    ax.plot(
                        [0] + timestamps,
                        [0] + diff_count,
                        label=diff_key,
                        markevery=((idx / idx_max) * 0.25, 0.25),
                    )
            else:
                # Plot outside the drawing range but preserve that each key is plotted for each subplot
                # This preserves the correct color order between them
                ax.plot([-1000], [-1000], label=diff_key)

    # Set limits. All axes are shared, setting once is enough
    axes[0][0].set_xlim(left=0)
    axes[0][0].set_ylim(bottom=0)
    # Format time axis
    ts_max = max(timestamps)
    fmt_time_axis(axes[0][0].xaxis, ts_max, nmarks=3)

    # Set a label for each row/column
    for idx, res in enumerate(all_resolvers):
        res = RESOLVER_PRETTY[res]
        if idx > 0:
            # Move the alignment of the tick labels, such that they don't overlap
            # The first tick label gets moved right, and the last ones left
            # That ensures that at neighboring plot they don't overlap
            ticklabels = axes[-1][idx - 1].get_xticklabels()
            # set the alignment for outer ticklabels
            ticklabels[0].set_ha("left")
            ticklabels[1].set_ha("left")
            ticklabels[-2].set_ha("right")
            ticklabels[-1].set_ha("right")

            axes[idx - 1][0].set_ylabel(res)
        if idx < len(all_resolvers) - 1:
            axes[-1][idx].set_xlabel(res)

    for idx_out, ax_outer in enumerate(axes):
        for idx, ax in enumerate(ax_outer):
            # Hide x labels and tick labels for all but outer plots.
            ax.label_outer()
            ax.tick_params(
                # x, y, both
                axis="both",
                # major, minor, both
                which="both",
                # in, out, inout
                direction="inout",
            )
            if idx_out < idx:
                ax.axis("off")

    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        ncols=2,
        # The upper right hand corner of the legend
        loc="upper right",
        # must be places on the right hand (1.0) upper (1.0) corner
        bbox_to_anchor=(1.0, 1.0),
        # of the specified axes. [0][-1] picks the upper right hand subfigure
        bbox_transform=axes[0][-1].transAxes,
    )

    fig.supxlabel("Runtime in HH:MM")
    fig.supylabel("Occurence of Difference Categories in Resolver Comparisons")
    fig.suptitle("Difference Categories")
    plt.savefig("fuzz-resolver-comparisons-diff-category.svg")
    plt.show()


register_cb(difference_category_plot)

# %%


# TODO Maybe show something about significant differences

# TODO add a message byte count to the metadata

# %%
ts_max = 21590.552973723
nmarks = 3

# %%
minor_unit: int = 3600
major_unit: int = round(ts_max / minor_unit / (nmarks - 1)) * minor_unit

# %%
major_unit, minor_unit

# %%
round(ts_max / minor_unit / (nmarks - 1))

# %%
