# IronSift
'Where's Waldo?'


ronSift

IronSift is a high-performance, Rust-based cybersecurity tool designed to sift through massive logs and identify suspicious machines in a fleet.

It uses DBSCAN Clustering to identify machines that deviate from the consensus behavior of the fleet (the "Iron" consensus).

Features

Multivariate Analysis: Detects threats based on 5 dimensions:

Process Name

Parent Process

User ID (UID)

Execution Path (e.g., /tmp vs /usr/bin)

Argument Entropy (Detects obfuscation)

Scale Invariant: Works on 10 logs or 10 million logs.

Zero Config: Unsupervised learning requires no prior knowledge of attack signatures.

Quick Start

Generate a massive dataset:

cargo run --bin generator


Sift the data:

cargo run --bin ironsift


Logic

IronSift treats every machine as a vector in N-dimensional space.

Normal machines cluster tightly together (distance ≈ 0).

Compromised machines drift away due to rare processes, strange paths, or high entropy.