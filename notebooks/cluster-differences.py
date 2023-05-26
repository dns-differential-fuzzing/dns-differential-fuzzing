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

# %%

import json
import os
import os.path
import shutil
import warnings
from collections import Counter, defaultdict
from dataclasses import dataclass
from glob import glob
from typing import Any, Generic, TypeVar

# import mplcursors
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from common_functions import open_file
from IPython.display import Markdown, display
from matplotlib.gridspec import GridSpec
from serde.json import from_json
from sklearn.cluster import SpectralBiclustering
from sklearn.exceptions import ConvergenceWarning

T = TypeVar("T")


@dataclass(order=True)
class SortableTuple(Generic[T]):
    """
    Prevent that `np.argsort` is looking into a tuple and treating it as another dimension.
    This is achieved by simply wrapping the tuple, thus inheriting its sorting order.
    Since it no longer is a plain tuple numpy will not further expand it.
    """

    first: Any


plt.rcParams["savefig.bbox"] = "tight"
plt.rcParams["figure.autolayout"] = True

# %% [raw]
# basepath = sorted(glob("/mnt/data/Downloads/dnsdiff/20??-??-?? *"))[-1]
# clusteroutput = "/mnt/data/Downloads/dnsdiff/clusteroutput"
#
# resolver_configurations = sorted(
#     {os.path.basename(folder) for folder in glob(os.path.join(basepath, "*", "*"))}
# )
# basepath, resolver_configurations

# %% [raw]
# for resolver_configuration in resolver_configurations:
#     y_labels = []
#     raw_data = []
#     for file in glob(
#         os.path.join(basepath, "*", resolver_configuration, "key-differences.json")
#     ):
#         keys = from_json(set, open_file(file, "rt").read())
#         raw_data.append(keys)
#         y_labels.append(os.path.basename(os.path.dirname(os.path.dirname(file))))
#     all_keys = list({key for keyset in raw_data for key in keyset})
#
#     data = np.array(
#         [[(1 if key in keyset else 0) for key in all_keys] for keyset in raw_data]
#     )
#
#     # Expand the cluster sizes until it no longer converges
#     x_cluster, y_cluster = 4, 4
#     # x_cluster_prev, y_cluster_prev
#     grow_x = True
#     grow_y = True
#     with warnings.catch_warnings():
#         warnings.filterwarnings("error")
#         while grow_x or grow_y:
#             if grow_x:
#                 try:
#                     n_clusters = (x_cluster + 1, y_cluster)
#                     print(f"Try converging of {n_clusters}")
#                     model = SpectralBiclustering(
#                         n_clusters=n_clusters, method="log", random_state=0
#                     )
#                     model.fit(data)
#                     x_cluster += 1
#                 except ConvergenceWarning as converge:
#                     grow_x = False
#
#             if grow_y:
#                 try:
#                     n_clusters = (x_cluster, y_cluster + 1)
#                     print(f"Try converging of {n_clusters}")
#                     model = SpectralBiclustering(
#                         n_clusters=n_clusters, method="log", random_state=0
#                     )
#                     model.fit(data)
#                     y_cluster += 1
#                 except ConvergenceWarning as converge:
#                     grow_y = False
#             if x_cluster == 30:
#                 grow_x = False
#             if y_cluster == 30:
#                 grow_y = False
#
#     n_clusters = (x_cluster, y_cluster)
#     model = SpectralBiclustering(n_clusters=n_clusters, method="log", random_state=0)
#     model.fit(data)
#
#     plt.close()
#     plt.rcParams["figure.figsize"] = (20, 15)
#     plt.rcParams["savefig.bbox"] = "tight"
#     # plt.rcParams["figure.autolayout"] = False
#     plt.rcParams["figure.constrained_layout.use"] = True
#
#     # Sort keys first on cluster and second lexicographical within
#     column_sort_idxs = np.argsort(
#         [SortableTuple((col, key)) for col, key in zip(model.column_labels_, all_keys)]
#     )
#     row_sort_idxs = np.argsort(
#         [SortableTuple((row, label)) for row, label in zip(model.row_labels_, y_labels)]
#     )
#
#     # Plot the re-arranged data
#     fit_data = data[row_sort_idxs]
#     fit_data = fit_data[:, column_sort_idxs]
#     # plt.gca().matshow(fit_data, cmap=plt.cm.Blues, aspect="auto")
#
#     # Calculate a unique color per xy cluster
#     # Combine the color with a tranparency (from the original data)
#     fit_data_color = np.add.outer(
#         (np.sort(model.row_labels_) % 2),
#         (np.sort(model.column_labels_) % 2) * 2,
#     )
#
#     fdc2color = {
#         0: (255, 0, 0),
#         1: (0, 255, 255),
#         2: (0, 0, 255),
#         3: (255, 255, 0),
#     }
#     img = []
#     for fd_row, fdc_row in zip(fit_data, fit_data_color):
#         row = []
#         for fd, fdc in zip(fd_row, fdc_row):
#             r, g, b = fdc2color[fdc]
#             pixel = (r, g, b, fd * 240 + 15)
#             row.append(pixel)
#         img.append(row)
#     plt.gca().matshow(img, aspect="auto")
#
#     # # Place a grey shade over the image to symbolize the distinct regions
#     # plt.gca().matshow(
#     #     np.add.outer(
#     #         np.sort(model.row_labels_),
#     #         np.sort(model.column_labels_),
#     #     ) % 2,
#     #     cmap=plt.cm.Greys,
#     #     alpha=0.3,
#     #     aspect="auto",
#     # )
#
#     # Sort entities and features matching to the clustering
#     raw_data_reordered = [raw_data[idx] for idx in row_sort_idxs]
#     y_labels_reordered = [y_labels[idx] for idx in row_sort_idxs]
#     keys_reordered = [all_keys[idx] for idx in column_sort_idxs]
#
#     # Print first entity per row-cluster
#     print()
#     clustersizes: Counter[int] = Counter(model.row_labels_)
#     last_row_cluster_id = None
#     for row_cluster_id, label, raw_data in zip(
#         sorted(model.row_labels_), y_labels_reordered, raw_data_reordered
#     ):
#         if row_cluster_id != last_row_cluster_id:
#             # Copy instances for each cluster into a separate folder
#             outdir = ""
#             if clusteroutput is not None:
#                 sourcedir = os.path.join(basepath, label, resolver_configuration)
#                 outdir = os.path.join(
#                     clusteroutput,
#                     resolver_configuration,
#                     f"{label}-clustersize-{clustersizes[row_cluster_id]}",
#                 )
#                 os.makedirs(outdir, exist_ok=True)
#                 shutil.copytree(sourcedir, outdir, dirs_exist_ok=True)
#
#             mdout = [
#                 f"* [`{label}`](./{outdir.replace('/mnt/data/Downloads/', './')}/fulldiff.txt) (Size: {clustersizes[row_cluster_id]})"
#             ]
#             for key in sorted(raw_data):
#                 mdout.append(f"    * `{key}`")
#             mdout.append(
#                 f"\n`cargo run --release --bin fuzzer  -- single {outdir}/fuzz-suite.json {resolver_configuration.replace('-', ' ')}`"
#             )
#
#             display(Markdown("\n".join(mdout)))
#             last_row_cluster_id = row_cluster_id
#
#     # Add labels for the features
#     _locs, new_labels = plt.xticks(
#         list(range(len(keys_reordered))),
#         keys_reordered,
#         rotation=90,
#     )
#
#     # plt.yticks(
#     #     list(range(len(y_labels_reordered))),
#     #     y_labels_reordered,
#     #     fontfamily="monospace",
#     # )
#
#     # cursor = mplcursors.cursor(hover=mplcursors.HoverMode.Transient)
#     # @cursor.connect("add")
#     # def on_add(sel):
#     #     x, y = sel.index
#     #     sel.annotation.set(text=f"{keys_reordered[y]}\n{y_labels_reordered[x]}")
#     #     # sel.annotation.set(text=f"{sel.index}")
#     #     # raise Exception(repr(sel.index))
#
#     plt.title(f"{resolver_configuration} {n_clusters}")
#     plt.savefig(f"{resolver_configuration}-{n_clusters[0]}-{n_clusters[1]}.svg")
#     plt.show()


# %%
basepath = sorted(glob("/mnt/data/Downloads/dnsdiff/20??-??-?? *"))[-1]
# basepath = sorted(glob("/mnt/data/Downloads/dnsdiff/2023-04-18 23:53"))[-1]
clusteroutput = "/mnt/data/Downloads/dnsdiff/clusteroutput"

resolver_configurations = sorted(
    {
        os.path.basename(folder)
        for folder in glob(os.path.join(basepath, "*", "*"))
        if not folder.endswith(".json")
    }
)
basepath, resolver_configurations

# %%
special_fields_keys = [
    "#Additionals",
    "#Answers",
    "Authentic Data (AD)",
    "Authoritative (AA)",
    "Checking Disabled (CD)",
    "Messsage Type",
    "#Authority",
    "OP Code",
    "#Queries",
    "Recursion Available (RA)",
    "Recursion Desired (RD)",
    "Response Code",
    "Truncated (TC)",
]
keep_hyphen = ["pdns-recursor", "knot-resolver", "trust-dns"]


def display_field(value: str | bool | int | None) -> str:
    match value:
        case bool():
            if value:
                return "T"
            else:
                return "F"
        case int():
            return str(value)
        case str():
            return value
        case None:
            return ""


cluster_count_matrix: dict[str, dict[str, int]] = {}
cluster_sizes_matrix: dict[str, dict[str, int]] = {}
mdout = []

# Print the top largest clusters including information how they differ, steps to reproduce etc.
for resolver_configuration in resolver_configurations:
    fingerprint_clusters = defaultdict(list)
    for file in glob(
        os.path.join(basepath, "*", resolver_configuration, "fingerprint.json")
    ):
        with open_file(file, "rt") as f:
            fingerprint = f.read()
        fuzzid = os.path.basename(os.path.dirname(os.path.dirname(file)))
        fingerprint_clusters[fingerprint].append(fuzzid)

    clusters = sorted(
        [(len(ids), fp, ids) for fp, ids in fingerprint_clusters.items()], reverse=True
    )

    # Preserve the `-` in the resolver name
    resolvers = resolver_configuration
    for ridx, rname in enumerate(keep_hyphen):
        resolvers = resolvers.replace(rname, f"TMP{ridx}DNS")
    resolvers = resolvers.replace("-", " ")
    for ridx, rname in enumerate(keep_hyphen):
        resolvers = resolvers.replace(f"TMP{ridx}DNS", rname)

    resolver_left, resolver_right = resolvers.split(" ")
    # Save the number of clusters and the size of each cluster per pair
    cluster_count_matrix.setdefault(resolver_left, {})[resolver_right] = len(clusters)
    cluster_sizes_matrix.setdefault(resolver_left, {})[resolver_right] = clusters[0][0]

    mdout.append(f"# {resolver_configuration} (Clusters: {len(clusters)})")
    for count, fp, ids in clusters[:4]:
        ids.sort()
        clusterpath = f"{basepath}/{ids[0]}/{resolver_configuration}"
        mdout.append(
            f"""* Cluster of size {count}: [`{ids[0]}`]({clusterpath.replace('/mnt/data/Downloads/', './').replace(" ", "%20")}/fulldiff.txt)  """
        )

        mdout.append(
            f"""    `cargo run --release --bin fuzzer  -- single "{clusterpath}/fuzz-suite.postcard" {resolvers}`"""
        )

        fingerprint = json.loads(fp)
        mdout.append(f"""    |     | {" | ".join(special_fields_keys)} |""")
        mdout.append(
            f"""    | :-- | {" | ".join("--:" for _ in special_fields_keys)} |"""
        )
        mdout.append(
            f"""    | L   | {" | ".join(display_field(x) for x in fingerprint['special_fields'][0])} |"""
        )
        mdout.append(
            f"""    | R   | {" | ".join(display_field(x) for x in fingerprint['special_fields'][1])} |"""
        )

        mdout.append("""    """)
        mdout.append("""    **Key Differences**""")
        mdout.append("""    ```""")
        for key_diff in fingerprint["key_diffs"]:
            mdout.append(f"""    {key_diff}""")
        mdout.append("""    ```""")

        mdout.append("""    """)
        mdout.append("""    <details><summary>All</summary>""")
        mdout.append("""    """)
        for i in ids:
            path = f"{basepath}/{i}/{resolver_configuration}".replace(
                "/mnt/data/Downloads/", "./"
            ).replace(" ", "%20")
            mdout.append(f"""    [`{i}`]({path}/fulldiff.txt)""")
        mdout.append("""    """)
        mdout.append("""    </details>""")

fig = plt.figure(layout="constrained", figsize=(20, 5))

gs = GridSpec(1, 2, figure=fig)
ax1 = fig.add_subplot(gs[0, 0])
ax2 = fig.add_subplot(gs[0, 1])

resolv = sorted(cluster_count_matrix.keys())
sns.heatmap(
    [
        [
            cluster_count_matrix[rleft].get(
                rright, cluster_count_matrix[rright].get(rleft, 0.0)
            )
            for rright in resolv
        ]
        for rleft in resolv
    ],
    vmin=0,
    annot=True,
    fmt=".0f",
    xticklabels=resolv,
    yticklabels=resolv,
    ax=ax1,
)
ax1.set_title("Number of clusters clusters")
resolv = sorted(cluster_sizes_matrix.keys())
sns.heatmap(
    [
        [
            cluster_sizes_matrix[rleft].get(
                rright, cluster_sizes_matrix[rright].get(rleft, 0.0)
            )
            for rright in resolv
        ]
        for rleft in resolv
    ],
    vmin=0,
    annot=True,
    fmt=".0f",
    xticklabels=resolv,
    yticklabels=resolv,
    ax=ax2,
)
ax2.set_title("Largest clusters")

for idx, ax_ in enumerate(fig.axes):
    # ax.text(0.5, 0.5, "ax%d" % (i+1), va="center", ha="center")
    # ax.tick_params(labelbottom=False)
    if idx > 0:
        ax_.tick_params(labelleft=False)
plt.show()

display(Markdown("\n".join(mdout)))

# %%
