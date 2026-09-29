# Public-data attribution and provenance

## Selected source: CTU-13, scenario 11

- Dataset authors: Sebastian Garcia, Martin Grill, Jan Stiborek, and Alejandro Zunino; Stratosphere Laboratory, Czech Technical University.
- Project attribution: Garcia, Sebastian. Malware Capture Facility Project. Retrieved from [Stratosphere Laboratory](https://www.stratosphereips.org/datasets-ctu13).
- Related paper: Garcia et al., *An empirical comparison of botnet detection methods*, Computers & Security (2014), [DOI: 10.1016/j.cose.2014.05.011](https://doi.org/10.1016/j.cose.2014.05.011).
- [Official dataset description](https://www.stratosphereips.org/datasets-ctu13).
- [Scenario 11 README and attribution terms](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/README.md).
- [Selected bidirectional flow CSV](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/detailed-bidirectional-flow-labels/capture20110818-2.binetflow).
- License: the dataset page's structured metadata links to [CC BY 2.0](https://creativecommons.org/licenses/by/2.0/); the scenario README also requires project/author attribution. The data license applies to the dataset, not automatically to unrelated repository code.
- Source pages inspected and source file retrieved on 2026-09-29.

The chosen file is a CSV of flow records. The downloader fetches only that file, not executables, packet payloads, or the full dataset archive.

Pinned source size: `14596615` bytes.

Pinned SHA-256:

```text
cee542d4b5efe4fa1cd59b87ece5aaea9a13d8f0abe56cd07cee31590736428c
```

This is a project-observed pin from the official HTTPS download, not a publisher-signed checksum. It detects changes relative to the inspected bytes; it does not independently authenticate the authors' labels.

## Changes made by this project

The adapter selects explicitly originating normal/botnet labels, excludes ambiguous labels, checks selected measurements, converts CEST capture times to UTC, preserves duration as integer microseconds, replaces endpoint addresses with deterministic dataset-scoped hashes, detects duplicate source flows, sorts events, and writes provenance metadata.

Source and output hashes plus row counts are saved in each run's manifest. These transformations change the representation and the class distribution. They do not imply endorsement by the dataset authors. Hashing endpoint addresses is pseudonymization, not a guarantee of anonymization.

Raw and transformed records are excluded from Git. The repository includes commands to reproduce them and a compact manifest containing attribution and aggregate results. All use of the records in the future service will be explicitly described as **simulated replay of public capture data**.
