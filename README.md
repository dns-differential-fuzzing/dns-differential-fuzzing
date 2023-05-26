# ResolFuzz: DNS Resolver Fuzzer

This repository accompanies the paper submission "ResolFuzz: Differential Fuzzing of DNS Resolvers".

1. [Project Overview](#project-overview)
2. [Fuzzing the DNS Resolvers](#fuzzing-the-dns-resolvers)
    1. [Building the Containers](#building-the-containers)
    2. [Running ResolFuzz](#running-resolfuzz)
3. [Trophycase](#trophycase)
    1. [`000e35b0-ffa0-49c8-ba43-b46232891d91`: Deadwood refuses to answer queries with QCLASS ANY](#000e35b0-ffa0-49c8-ba43-b46232891d91-deadwood-refuses-to-answer-queries-with-qclass-any)
    2. [`0013bbeb-05b0-419b-8250-60b8c6efa50a`: resolved fails to answer CNAME queries to non-existing records](#0013bbeb-05b0-419b-8250-60b8c6efa50a-resolved-fails-to-answer-cname-queries-to-non-existing-records)
    3. [`016a13b1-5674-447d-98cf-9a864d73bd59`: BIND9 discards answers with mixed CLASS values](#016a13b1-5674-447d-98cf-9a864d73bd59-bind9-discards-answers-with-mixed-class-values)
    4. [`00ace827-cbd7-45bd-8528-f1ae34d7f655`: PowerDNS Recursors loops on DNAME records leading to large answers](#00ace827-cbd7-45bd-8528-f1ae34d7f655-powerdns-recursors-loops-on-dname-records-leading-to-large-answers)
    5. [`04970a0b-52a4-4cd3-8765-09c3374d0017`: Deadwood ignores messages with 0-byte](#04970a0b-52a4-4cd3-8765-09c3374d0017-deadwood-ignores-messages-with-0-byte)
    6. [`3fffab07-8e90-4c8a-999e-47ee3692381c`: resolved and trust-dns are vulnerable to traffic loops](#3fffab07-8e90-4c8a-999e-47ee3692381c-resolved-and-trust-dns-are-vulnerable-to-traffic-loops)
    7. [`db1d577b-3a3c-4eac-9c1f-57ce6a5ec38e`: Unbound returns record of wrong class](#db1d577b-3a3c-4eac-9c1f-57ce6a5ec38e-unbound-returns-record-of-wrong-class)


## Project Overview

* `fuzzer`: contains the Coordinator component of ResolFuzz.
* `fuzzer-protocol`: defines a TCP based protocol used to remote control the fuzzee.
    It also provides access to information like the code coverage gathered by the fuzzee.
* `libcoverage`: provides the hooks for the LLVM source code coverage functions.
    It also uses `fuzzer-protocol`to spawn the fuzzee server.
* `dnsauth`: contains Helper component and type definitions.
    The main binary is `dnsauth`
* `examples`: Container definitions for the DNS resolvers are stored here.
    This includes build scripts to compile from source, all our compiler modifications, and the resolver configurations to run them.
* `notebooks`: contains Jupyter Notebooks for further output analysis and image generation.

## Fuzzing the DNS Resolvers

The project requires that Rust is available.
For the containers, either podman or docker is necessary.

### Building the Containers

In the `examples/` directory execute the `build_fuzzing_container.sh` script.
This will build all the containers necessary for the fuzzing process.

### Running ResolFuzz

Executing `cargo run --release --bin fuzzer` is enough to start the fuzzing, but options are available.

```text
$ cargo run --release --bin fuzzer -- --help
Usage: fuzzer [OPTIONS] [COMMAND]

Commands:
  single      Execute a single FuzzSuite
  spawn       Spawn a container running the resolver and all static AuthNS
  show-stats  Show statistics about the fuzzing
  help        Print this message or the help of the given subcommand(s)

Options:
      --reset-state               Ignore any existing fuzzing state and start from scratch
      --dump-diffs <DUMP_DIFFS>   Dump any found differences into this directory
      --resolvers <RESOLVERS>...  
  -h, --help                      Print help
```

You can specify which resolvers you want to use, by specifying the image names.
All differences can be dumped for later analysis.
ResolFuzz will show a UI on the terminal during the fuzzing providing live statistics.

The **single** command allows re-running a previously dumped `FuzzSuite`.

```test
$ cargo run --release --bin fuzzer -- single --help
Execute a single FuzzSuite

Usage: fuzzer single [OPTIONS] <SUITE> <FUZZEES>...

Arguments:
  <SUITE>       Path to the FuzzSuite file
  <FUZZEES>...  List of fuzzees to run

Options:
      --keep  Keep the directory with all output files
  -h, --help  Print help
```

Similarly, **show-stats** loads the live statistics from a previous run.
The path can either be to a single JSON file or the `stats` folder inside the `--dump-diffs` folder.
For interactive analysis, you can spawn a single container and load a `FuzzSuite` using the **spawn** command.
This will spawn a container and perform all the pre-fuzz steps, but not close the container afterward.
Using `podman exec -it -l bash` you can enter the container and inspect it.

```test
$ cargo run --release --bin fuzzer -- spawn --help
Spawn a container running the resolver and all static AuthNS

Usage: fuzzer spawn [OPTIONS] <SUITE> <FUZZEE>

Arguments:
  <SUITE>   Path to the FuzzSuite file
  <FUZZEE>  Fuzzee container to spawn

Options:
      --keep  Keep the directory with all output files
  -h, --help  Print help

```

## Trophycase


### `000e35b0-ffa0-49c8-ba43-b46232891d91`: Deadwood refuses to answer queries with QCLASS ANY

Deadwood refuses to answer on client queries with a QCLASS of ANY.

```text
    .fuzz_case.client_query.queries.#count           1
    .fuzz_case.client_query.queries.0.name           fnbhv.test.fuzz.
    .fuzz_case.client_query.queries.0.query_class    ANY
    .fuzz_case.client_query.queries.0.query_type     SRV
```

### `0013bbeb-05b0-419b-8250-60b8c6efa50a`: resolved fails to answer CNAME queries to non-existing records

resolved misinterprets a NODATA answer when queried for CNAME type.

```text
    .fuzz_case.client_query.queries.#count               1             1
    .fuzz_case.client_query.queries.0.name               test.fuzz.    test.fuzz.
    .fuzz_case.client_query.queries.0.query_class        IN            IN
    .fuzz_case.client_query.queries.0.query_type         CNAME         CNAME

 .  .fuzz_result.fuzzee_response.header.response_code    NoError       ServFail      ResolvedServFailOnNoData
 .  .fuzz_result.response_idxs.#count                    1             2             MetaDiff
    .fuzz_result.response_idxs.0                         usize::MAX    usize::MAX
 .  .fuzz_result.response_idxs.1                                       usize::MAX    TrailingRetransmissions
 .  .resolver_name                                       bind9         resolved      ResolverName
```

Neither resolver asks a question that can be answered by the fuzzer.
The fuzzer responds with an empty response, but with `NoError` set as the response code.
This means the name exists, but the queries TYPE is not available.
This happens if other TYPEs are available, or the name is an empty non-terminal, i.e., no type exists, but a sub-domain exists.

resolved fails to correctly process this, but only if the query type is CNAME.

### `016a13b1-5674-447d-98cf-9a864d73bd59`: BIND9 discards answers with mixed CLASS values

BIND9 fails to retrieve the answer and returns a ServFail, likely due to the mixed CLASS values in the AuthNS response.

Deadwood, Unbound, and pdns-recursor manage to return an answer.

```text
 .  .fuzz_result.fuzzee_response.answers.#count           1
 *  .fuzz_result.fuzzee_response.answers.0.dns_class      IN
 *  .fuzz_result.fuzzee_response.answers.0.name_labels    gechu.0000.fuzz.
 *  .fuzz_result.fuzzee_response.answers.0.rdata          kyadc.0000.fuzz.
 *  .fuzz_result.fuzzee_response.answers.0.rr_type        NS
 *  .fuzz_result.fuzzee_response.answers.0.ttl            86400

```

Only Unbound returns this name server entry.
The CLASS is ok, since the client queried for ANY class.
But the RR type of TXT is unusual, since the query is explicitly for the NS type.

```text
 .  .fuzz_result.fuzzee_response.name_servers.#count           1
 *  .fuzz_result.fuzzee_response.name_servers.0.dns_class      HS
 *  .fuzz_result.fuzzee_response.name_servers.0.name_labels    hcpln.0000.fuzz.
 *  .fuzz_result.fuzzee_response.name_servers.0.rdata          pzies.test.fuzz.
 *  .fuzz_result.fuzzee_response.name_servers.0.rr_type        TXT
 *  .fuzz_result.fuzzee_response.name_servers.0.ttl            86400
```

### `00ace827-cbd7-45bd-8528-f1ae34d7f655`: PowerDNS Recursors loops on DNAME records leading to large answers

Self-DoS similar to [CVE-2022-48256] but found for PowerDNS Recursor and using DNAME records.
During the probing phase of QNAME Minimization PowerDNS Recursor finds a DNAME record which is a self-loop.
The client queries for `fjlkt.kvomi.test.fuzz.`, and PowerDNS Recursor starts by querying for `kvomi.0002.fuzz.`.
The value `BWZqbGt0BDAwMDAEZnV6egA=` decodes to `fjlkt.test.fuzz.`, thus the DNAME shows that a level more must be inserted.

```text
.fuzz_case.server_responses.0.answers.#count        1
.fuzz_case.server_responses.0.answers.0.dns_class   IN
.fuzz_case.server_responses.0.answers.0.name_labels test.fuzz.
.fuzz_case.server_responses.0.answers.0.rdata       BWZqbGt0BDAwMDAEZnV6egA=
.fuzz_case.server_responses.0.answers.0.rr_type     RTYPE39
.fuzz_case.server_responses.0.answers.0.ttl         300
.fuzz_case.server_responses.0.queries.#count        1
.fuzz_case.server_responses.0.queries.0.name        kvomi.test.fuzz.
.fuzz_case.server_responses.0.queries.0.query_class IN
.fuzz_case.server_responses.0.queries.0.query_type  A
```

This leads PowerDNS Recursor to emit an answer with 32 resource records, some of them duplicate, while indicating a `ServFail`.
There are multiple CNAME, each with another layer of `fjlkt` label.
Besides 16 CNAME records, there are a further 16 DNAME records (RTYPE39), each identical to each other.

```text
 .  .fuzz_result.fuzzee_response.answers.#count           32

 .  .fuzz_result.fuzzee_response.answers.0.dns_class      IN
 .  .fuzz_result.fuzzee_response.answers.0.name_labels    fjlkt.kvomi.0000.fuzz.
 .  .fuzz_result.fuzzee_response.answers.0.rdata          fjlkt.kvomi.fjlkt.0000.fuzz.
 .  .fuzz_result.fuzzee_response.answers.0.rr_type        CNAME
 .  .fuzz_result.fuzzee_response.answers.0.ttl            300
 .  .fuzz_result.fuzzee_response.answers.1.dns_class      IN
 .  .fuzz_result.fuzzee_response.answers.1.name_labels    fjlkt.kvomi.fjlkt.0000.fuzz.
 .  .fuzz_result.fuzzee_response.answers.1.rdata          fjlkt.kvomi.fjlkt.fjlkt.0000.fuzz.
 .  .fuzz_result.fuzzee_response.answers.1.rr_type        CNAME
 .  .fuzz_result.fuzzee_response.answers.1.ttl            300
 .  .fuzz_result.fuzzee_response.answers.2.dns_class      IN
 .  .fuzz_result.fuzzee_response.answers.2.name_labels    fjlkt.kvomi.fjlkt.fjlkt.0000.fuzz.
 .  .fuzz_result.fuzzee_response.answers.2.rdata          fjlkt.kvomi.fjlkt.fjlkt.fjlkt.0000.fuzz.
 .  .fuzz_result.fuzzee_response.answers.2.rr_type        CNAME
 .  .fuzz_result.fuzzee_response.answers.2.ttl            300

 .  .fuzz_result.fuzzee_response.answers.16.dns_class     IN
 .  .fuzz_result.fuzzee_response.answers.16.name_label    0000.fuzz.
 .  .fuzz_result.fuzzee_response.answers.16.rdata         BWZqbGt0BDAwMDAEZnV6egA=
 .  .fuzz_result.fuzzee_response.answers.16.rr_type       RTYPE39
 .  .fuzz_result.fuzzee_response.answers.16.ttl           300
 .  .fuzz_result.fuzzee_response.answers.17.dns_class     IN
 .  .fuzz_result.fuzzee_response.answers.17.name_label    0000.fuzz.
 .  .fuzz_result.fuzzee_response.answers.17.rdata         BWZqbGt0BDAwMDAEZnV6egA=
 .  .fuzz_result.fuzzee_response.answers.17.rr_type       RTYPE39
 .  .fuzz_result.fuzzee_response.answers.17.ttl           300
 .  .fuzz_result.fuzzee_response.answers.18.dns_class     IN
 .  .fuzz_result.fuzzee_response.answers.18.name_label    0000.fuzz.
 .  .fuzz_result.fuzzee_response.answers.18.rdata         BWZqbGt0BDAwMDAEZnV6egA=
 .  .fuzz_result.fuzzee_response.answers.18.rr_type       RTYPE39
 .  .fuzz_result.fuzzee_response.answers.18.ttl           300
```

[CVE-2022-48256]: https://nvd.nist.gov/vuln/detail/CVE-2022-48256

### `04970a0b-52a4-4cd3-8765-09c3374d0017`: Deadwood ignores messages with 0-byte

Deadwood fails to process messages with embedded 0-byte, such as `vyfmt.test.fuzz\000.`.

```text
    .fuzz_case.client_query.queries.#count           1
    .fuzz_case.client_query.queries.0.name           vyfmt.test.fuzz\000.
    .fuzz_case.client_query.queries.0.query_class    IN
    .fuzz_case.client_query.queries.0.query_type     RRSIG
```

### `3fffab07-8e90-4c8a-999e-47ee3692381c`: resolved and trust-dns are vulnerable to traffic loops

Both resolved and trust-dns are vulnerable to a self-sustaining DoS attack.
When receiving a message with message_type response they answers with a FormErr.
All other resolvers do not answer at all.

Answering is a problem because this enables a self-sustaining DoS by having messages ping-pong between two broken resolvers without stopping.
Assume there is resolver A with IP A.A.A.A and resolver B with B.B.B.B.
The attacker mallory M with IP M.M.M.M now spoofs a packet with src: B.B.B.B and dst: A.A.A.A.
Resolver A will send a response back to B and since B answers messages, even if they are responses, B will send back a FormErr to A.
Here the cycle starts over and both A and B will now repeatedly send FormErr messages until the message gets lost in the network.

This is the resolved part of a comparison with BIND9.

```text
    .fuzz_case.client_query.header.additional_count          0
    .fuzz_case.client_query.header.answer_count              0
    .fuzz_case.client_query.header.authentic_data            false
    .fuzz_case.client_query.header.authoritative             false
    .fuzz_case.client_query.header.checking_disabled         false
    .fuzz_case.client_query.header.id                        0
    .fuzz_case.client_query.header.message_type              response
    .fuzz_case.client_query.header.name_server_count         0
    .fuzz_case.client_query.header.op_code                   query
    .fuzz_case.client_query.header.query_count               0
    .fuzz_case.client_query.header.recursion_available       false
    .fuzz_case.client_query.header.recursion_desired         true
    .fuzz_case.client_query.header.response_code             NoError
    .fuzz_case.client_query.header.truncated                 false
    .fuzz_result.fuzzee_queries.#count                       0
 .  .fuzz_result.fuzzee_response.header.additional_count     0                                     ErrorClientNoRrInAnswer
 .  .fuzz_result.fuzzee_response.header.answer_count         0                                     ErrorClientNoRrInAnswer
 *  .fuzz_result.fuzzee_response.header.authentic_data       false
 *  .fuzz_result.fuzzee_response.header.authoritative        false
 .  .fuzz_result.fuzzee_response.header.checking_disabled    false                                 NoEdnsSupport
 .  .fuzz_result.fuzzee_response.header.id                   25036                                 DnsId
 *  .fuzz_result.fuzzee_response.header.message_type         response
 .  .fuzz_result.fuzzee_response.header.name_server_count    0                                     ErrorClientNoRrInAnswer
 *  .fuzz_result.fuzzee_response.header.op_code              query
 *  .fuzz_result.fuzzee_response.header.query_count          0
 *  .fuzz_result.fuzzee_response.header.recursion_available  true
 *  .fuzz_result.fuzzee_response.header.recursion_desired    false
 *  .fuzz_result.fuzzee_response.header.response_code        FormErr
 *  .fuzz_result.fuzzee_response.header.truncated            false
 .  .resolver_name                                           resolved                              ResolverName
```

### `db1d577b-3a3c-4eac-9c1f-57ce6a5ec38e`: Unbound returns record of wrong class

Unbound accepts and returns a RR of class CH to the client.
The client asked for IN.

```text
    .fuzz_case.client_query.queries.#count                1
    .fuzz_case.client_query.queries.0.name                glsbm.test.fuzz.
    .fuzz_case.client_query.queries.0.query_class         IN
    .fuzz_case.client_query.queries.0.query_type          A

 .  .fuzz_result.fuzzee_response.answers.#count           1
 .  .fuzz_result.fuzzee_response.answers.0.dns_class      CH
 .  .fuzz_result.fuzzee_response.answers.0.name_labels    glsbm.0000.fuzz.
 .  .fuzz_result.fuzzee_response.answers.0.rdata          88.158.204.111
 .  .fuzz_result.fuzzee_response.answers.0.rr_type        A
 .  .fuzz_result.fuzzee_response.answers.0.ttl            86400

 .  .resolver_name                                        unbound
```
