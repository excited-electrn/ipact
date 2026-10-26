# Testing and development

## GitHub Actions

The [build workflow](../.github/workflows/ci.yml) runs on Ubuntu 24.04 for every push and pull request. It can also be started manually from the Actions page. It configures a Debug build, compiles the library and all examples and tests, then runs the three CTest programs. A failed build or test fails the workflow. Each test has a limit of 120 seconds, and the whole job has a limit of 15 minutes.

The workflow uses the build tools already installed on the Ubuntu runner. Tests run without root access or a TUN interface.

## Build and run tests

Use a Linux shell from the repository root.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

CMake registers three test programs. None opens a TUN interface or requires root access. Debug builds are a useful default when changing the protocol.

| Program | Coverage |
| :--- | :--- |
| `unit_tests` | Checksums, sequence wraparound, packet parsing, options, byte queues, RTT estimates, and selective acknowledgment ranges |
| `sim_test` | Transfers under loss, delay, duplication, reordering, small buffers, connection failure, and close scenarios |
| `fuzz_parse` | Random and mutated inputs for IPv4, TCP, and option parsers |

CTest runs the standalone fuzz program with 200000 inputs. Run any program directly when investigating a failure.

```sh
./build/unit_tests
./build/sim_test
./build/fuzz_parse 500000
```

## Network simulation

The simulator connects two `TcpLayer` instances through an in memory network. It controls time and packet delivery, so retransmission and timeout scenarios can run without waiting for real time to pass.

Scenarios cover clean transfer, heavy packet loss, sequence wraparound, option combinations, slow readers, refused connections, lost handshake packets, fast retransmit, a network that stops delivering packets, simultaneous close, and reset. A further test varies loss and delay across 150 random seeds. Tests compare transferred bytes with a known pattern and check buffer and sequence invariants.

When adding a regression test, use a fixed seed or an explicit packet drop rule so that another developer can reproduce the same failure.

## Sanitizers

With a compiler that supports the requested sanitizers, build into a separate directory.

```sh
cmake -S . -B build_asan -DCMAKE_BUILD_TYPE=Debug -DIPACT_SANITIZE=address,undefined
cmake --build build_asan --parallel
ctest --test-dir build_asan --output-on-failure
```

Use a separate build for the thread sanitizer because it cannot be combined with the address sanitizer.

```sh
cmake -S . -B build_tsan -DCMAKE_BUILD_TYPE=Debug -DIPACT_SANITIZE=thread
cmake --build build_tsan --parallel
ctest --test-dir build_tsan --output-on-failure
```

The protocol tests do not exercise the public blocking API over a real TUN interface. To inspect live thread behavior, run examples from the sanitizer build with the setup in the [setup guide](SETUP.md).

## Coverage guided fuzzing

The default CMake target defines `FUZZ_STANDALONE`. For Clang libFuzzer, compile the parser driver directly without that definition.

```sh
clang++ -std=c++20 -fsanitize=fuzzer,address,undefined -Iinclude -Isrc tests/fuzz_parse.cpp -o fuzz_parse
./fuzz_parse -max_total_time=60
```

The driver sends arbitrary data to the IPv4, TCP, and TCP option parsers. Invalid input should be rejected without a crash, invalid memory access, or an endless loop.

## Changes to the protocol

Keep changes near the layer that owns the behavior. Add a unit test for a parser or utility change, and a simulated transfer for a change to delivery or recovery. Run the existing suite before testing a live connection. Use PCAP files and connection statistics to inspect live behavior when needed.

Build directories other than `build`, generated capture files, CSV files, plots, and Python environments are not all covered by the current ignore rules. Keep generated files out of commits.

Return to the [README](../README.md).
