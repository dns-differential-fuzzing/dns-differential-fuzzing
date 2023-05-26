# Resolver Images

## Image Layout

* `/config`: Folder bind-mounted from the outside.
    * `/config/config.toml`: Zones information for the static AuthNS.
        Contains the root and fuzz zone.
    * `/config/fuzz-suite.postcard`: File containing a list of `FuzzCases`.
        Each consists of a client query, AuthNS responses, and cache check queries.
    * `/config/background_activity_profile.postcard` (optional): Stored view of the code coverage associated with background activity.
        The file gets generated if missing, but providing it provides a speedup.
* `/fuzzee`: Plaintext file naming the resolver packaged in this image.
* `/usr/local`: All resolver files, i.e., binaries, configurations, auxiliary data.
    This data is copied from the stage 1 build and extended with extra executables.

    * `/usr/local/bin/dnsauth`: Fuzzing driver for a resolver. It acts as the DNS client and DNS AuthNS
    * `/usr/local/bin/fuzzee`: Startup command for the resolver.
        This should start the resolver in foreground mode (no daemon).

## Compiling Resolver

The Dockerfile implements a two-stage build process for DNS resolver.
The first stage builds the resolver and configures it to install into `/`usr/local`.
The second stage installs runtime dependencies and copies the `/usr/local` directory.
This ensures that the final image is smaller since no buildtime dependencies are included.

Each resolver should be configured to have a minimalistic set of features.
Features such as geoip lookups, DoH, Response Policy Zones (RPZ), or remote control are not useful.
These features are not explored during fuzzing and only introduce unnecessary randomness.

The resolvers should be built as static executables if possible.
For building the two scripts `cc` and `cxx` should be used if the source code is C or C++.
They build the executable with LLVM coverage information using the `libcoverage.a` static library.

## Runtime Configuration

The resolvers should each have a functioning configuration file with them.
They need to listen for incoming DNS queries on `127.0.0.1:53`.
As root hints the single server `127.64.1.1` must be configured.

```text
.           3600000 NS  ns-root.ns.
ns-root.ns. 3600000 A   127.64.1.1
```

IPv4-only operation is fine.
Logging messages should be directed to stdout/stderr.
