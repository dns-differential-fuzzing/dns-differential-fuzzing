# libcoverage

`libcoverage` is a static library implementing the LLVM Sanitizer Coverage hooks.
It initializes the guards and global counters,
Multiple environment variables are available to control how the fuzzee behaves.
They all start with `FUZZEE_`.

* `FUZZEE_COUNTER_ON_EXIT`: If set print a summary about the counter status when exiting the process.
* `FUZZEE_STARTUP_DEBUG`: If set print some diagnostic information during the initialization of the tracing guards.
* `FUZZEE_LISTEN_ADDR`: Needs to be an address to create a listening socket in the form `localhost:1234` or `127.0.0.1:1234`.
    A TCP listening socket is created, which speaks the [fuzzer-protocol](../fuzzer-protocol/) and allows remote access to the tracing counters, and resetting the counters.
