#!/usr/bin/env python3
from __future__ import annotations

import json
import lzma
import math
import sys
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

import numpy as np
import scipy.cluster.hierarchy as cluster
from matplotlib import pyplot as plt
from matplotlib.axes import Axes
from matplotlib.offsetbox import AnnotationBbox, OffsetImage
from scipy.spatial.distance import pdist


def print_help(pgrm: str) -> None:
    print(
        f"""Usage: ./{pgrm} FUZZEROUTPUT

    The FUZZEROUTPUT file TODO
    """
    )
    sys.exit(1)


@dataclass
class Counter:
    counts: list[int]

    @classmethod
    def new_with_length(cls, init: int, l: int) -> Counter:
        return Counter([init for _ in range(0, l)])

    def __len__(self) -> int:
        return len(self.counts)

    def max_pairwise(self, other: Counter) -> None:
        assert len(self) == len(other), "self and other need to have the same length"
        self.counts = [max(a, b) for a, b in zip(self.counts, other.counts)]

    def shrink_by_pattern(self, pattern: Counter) -> None:
        assert len(self) == len(
            pattern
        ), "self and pattern need to have the same length"
        self.counts = [s for s, p in zip(self.counts, pattern.counts) if p > 0]

    def distance(self, other: Counter) -> int:
        assert len(self) == len(other), "self and other need to have the same length"
        return sum(abs(a - b) for a, b in zip(self.counts, other.counts))

    def normalize_counter(self, other: Counter) -> None:
        assert len(self) == len(other), "self and other need to have the same length"
        self.counts = [(s * 255) // p for s, p in zip(self.counts, other.counts)]

    def convert_to_image(self) -> Any:
        # let img_size = ((self.counter.len() as f64).sqrt().floor() + 1.) as u32;
        img_size = math.floor(math.sqrt(len(self))) + 1
        img = np.zeros((img_size, img_size), dtype=np.float32)
        for idx, count in enumerate(self.counts):
            x = idx // img_size
            y = idx % img_size
            img[x, y] = count / 255
        return img


@dataclass
class Input:
    input: str

    def __str__(self) -> str:
        return self.input


def read_fuzzer_output(
    file: str,
) -> dict[str, tuple[Counter, list[Input]]]:
    data = json.load(lzma.open(file))
    # The outer layer only contains version information
    data = data["Version2"]
    res = {}
    # hash, data
    for h, d in data["counters"]:
        counter = Counter(counts=d[0]["counter"])
        inputs = [Input(i) for i in d[1]]
        res[h] = (counter, inputs)

        if len(res) >= 100:
            break
    return res


def main() -> None:
    if len(sys.argv) < 2:
        print_help(sys.argv[0])

    fuzzer_output = read_fuzzer_output(sys.argv[1])
    print(len(fuzzer_output))

    # Get a counter where all fields are set (!= 0) which are set in any counter
    counter_len = len(next(iter(fuzzer_output.values()))[0])
    elementwise_max = Counter.new_with_length(0, counter_len)
    print(len(elementwise_max))

    # Collect all the counters which are ever set
    for counter, _ in fuzzer_output.values():
        elementwise_max.max_pairwise(counter)

    # Remove all the parts which are always 0
    elementwise_max_shrunk = deepcopy(elementwise_max)
    elementwise_max_shrunk.shrink_by_pattern(elementwise_max)
    for counter, _ in fuzzer_output.values():
        counter.shrink_by_pattern(elementwise_max)
        counter.normalize_counter(elementwise_max_shrunk)
    elementwise_max = elementwise_max_shrunk
    elementwise_max.normalize_counter(elementwise_max)

    # pdist requires a 2-dimensional array, without any good reason
    # So convert the list into an list of 1-element lists to fullfill this requirement
    # The comparison lambda just has to take the 0th element every time
    counters_matrix: list[list[Counter]] = [[d[0]] for d in fuzzer_output.values()]
    distances_pairwise = pdist(
        counters_matrix, lambda a, b: a[0].distance(b[0]) / max(len(a[0]), len(b[0]))  # type: ignore
    )
    for threshold, method in [
        (2, "single"),
        (4, "average"),
        (5, "weighted"),
        (4, "centroid"),
        (5, "median"),
        (50, "ward"),
    ]:
        Z = cluster.linkage(distances_pairwise, method=method, optimal_ordering=True)
        plt.figure(figsize=(15, len(fuzzer_output) * 0.15 * 5))
        ax = plt.gca()
        labels = []
        for h, v in fuzzer_output.items():
            input_count = len(v[1])
            hash_ = h
            space = " " * 15
            # inputs = "\n".join(map(str, v[1]))
            labels.append(f"{input_count} - {hash_}{space}")
        dn = cluster.dendrogram(
            Z,
            color_threshold=threshold,
            distance_sort="ascending",  # type: ignore
            labels=labels,
            orientation="right",
            show_contracted=True,
            show_leaf_counts=True,
        )
        label_on_index = dn["ivl"]
        lbls = ax.get_ymajorticklabels()  # type: ignore # matplotlib does not have usable type annotations

        def offset_image(counter_hash: str, coord: tuple[int, int], ax: Axes) -> None:
            ctr = fuzzer_output[counter_hash][0]
            img = ctr.convert_to_image()
            im = OffsetImage(img, zoom=1)
            im.image.axes = ax  # type: ignore

            ab = AnnotationBbox(
                im,
                coord,
                xybox=(-12.0, 0.0),
                frameon=False,
                xycoords="data",
                boxcoords="offset points",
                pad=0,
            )
            ax.add_artist(ab)  # type: ignore # matplotlib does not have usable type annotations

        for idx, lbl in enumerate(lbls):
            counter_hash = label_on_index[idx].split(" - ")[1].split("\n")[0].strip()
            offset_image(counter_hash, lbl.get_position(), ax)

        plt.savefig(f"cluster-{method}.svg", bbox_inches="tight")
        print(f"Finished {method}")


if __name__ == "__main__":
    main()
