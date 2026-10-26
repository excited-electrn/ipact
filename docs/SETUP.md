# Setup and examples

## Build requirements

Use Linux with a compiler that supports C++20 and CMake 3.20 or newer. The library needs the C++ standard library, POSIX threads, Linux TUN support, and epoll. There are no external C++ library dependencies.

On Ubuntu or Debian, the following packages provide the build tools and commands used in this guide. Check that the installed CMake version meets the requirement.

```sh
sudo apt install build-essential cmake iproute2 netcat-openbsd socat
cmake --version
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
```

Run all commands from the repository root. Windows users need a Linux environment with working TUN support. Native Windows and macOS builds are not supported by the current implementation.

## Configure the TUN interface

The examples use this address layout.

| Side | Address | Owner |
| :--- | :--- | :--- |
| Host | `10.0.0.1` | Linux interface `tun0` |
| Stack | `10.0.0.2` | ipact inside the example program |

Choose an unused subnet before creating the interface. If `tun0` already exists, inspect its configuration instead of creating a second interface with the same name.

```sh
sudo ip tuntap add dev tun0 mode tun user "$(id -un)"
sudo ip addr add 10.0.0.1/24 dev tun0
sudo ip link set dev tun0 mtu 1500 up
ip addr show dev tun0
ip route get 10.0.0.2
```

The subnet route sends traffic for `10.0.0.2` into the TUN interface. The program reads these packets and writes replies back to Linux. Do not assign `10.0.0.2` to Linux because the stack handles that address itself. This local setup does not need IP forwarding or NAT.

A persistent interface owned by your user allows the examples to open it without sudo. Creating an interface without a configured owner normally requires root or the relevant network administration capability.

## Echo server

Start the server in one terminal.

```sh
./build/echo_server
```

Connect from another terminal and enter text.

```sh
nc 10.0.0.2 9000
```

The server echoes the bytes you send. Ctrl+C stops the client or server. Only one program should open `tun0` at a time.

## Client

Start a host echo service in one terminal.

```sh
socat TCP-LISTEN:7000,bind=10.0.0.1,reuseaddr,fork EXEC:cat
```

Run the ipact client from another terminal, with other ipact examples stopped.

```sh
./build/hello_client 10.0.0.1 7000 "hello from ipact"
```

The client sends the text and prints one received chunk and connection statistics. TCP is a byte stream, so a single receive call does not promise to return a complete application message.

## ICMP and packet inspection

Run `ping_responder`, then ping the stack from another terminal.

```sh
./build/ping_responder
```

```sh
ping 10.0.0.2
```

For raw packet inspection, stop the responder and run `./build/tun_dump`. Generate traffic from a second terminal. The dump program prints packets but does not answer them. These two examples use the fixed interface name `tun0`.

## Configuration

Set environment variables before starting a program. Presence switches are enabled whenever the variable exists, including when its value is `0`. Remove the variable to restore its default behavior.

| Variable | Default | Effect |
| :--- | :--- | :--- |
| `IPACT_LOG` | Absent | Enable debug output on standard error |
| `IPACT_TUN` | `tun0` | Select the interface for examples that use `EngineConfig::from_env()` |
| `IPACT_DROP_IN` | `0` | Drop incoming packets with a probability from 0 to 1 |
| `IPACT_DROP_OUT` | `0` | Drop outgoing packets with a probability from 0 to 1 |
| `IPACT_PCAP` | Empty | Record packets to the given PCAP file |
| `IPACT_NO_SACK` | Absent | Disable selective acknowledgment negotiation |
| `IPACT_NO_TS` | Absent | Disable timestamp negotiation |
| `IPACT_NO_WSCALE` | Absent | Disable window scale negotiation |
| `IPACT_CWND_LOG` | Absent | Record congestion statistics in `blast` only |

The public `ipact::Stack` uses `Options::tun_name` and `Options::local_ip`, which take precedence over engine defaults. In particular, `IPACT_TUN` does not override `Options::tun_name`. A nonempty `Options::pcap_path` overrides `IPACT_PCAP`. Other engine environment settings still apply to the public API.

## Packet capture and loss

```sh
IPACT_LOG=1 IPACT_PCAP=echo.pcap IPACT_DROP_IN=0.05 IPACT_DROP_OUT=0.05 ./build/echo_server
```

Open `echo.pcap` in Wireshark to inspect IP and TCP packets. Capture happens after the artificial loss decision, so packets discarded by these loss controls do not appear in the file. Use a writable output path.

## Congestion window plot

Start a host receiver in a separate terminal.

```sh
socat -u TCP-LISTEN:7000,bind=10.0.0.1,reuseaddr OPEN:received.bin,creat,trunc
```

Send one million bytes with a small amount of packet loss.

```sh
IPACT_CWND_LOG=cwnd.csv IPACT_DROP_OUT=0.02 ./build/blast 10.0.0.1 7000 1000000
```

Install the optional plotting library in a Python environment and generate the image.

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install matplotlib
python3 tools/plot_cwnd.py cwnd.csv cwnd.png
```

The chart shows the congestion window, bytes in flight, and slow start threshold. CSV values are measured in milliseconds and bytes. A threshold value of zero means no finite threshold has been set yet.

`blast` sends byte number `i` as `i % 251`. Verify the saved transfer after the receiver exits.

```sh
python3 -c 'from pathlib import Path; assert Path("received.bin").read_bytes() == bytes(i % 251 for i in range(1000000)); print("Transfer verified")'
```

## Slow reader

```sh
./build/slow_reader 5 received.bin
```

Send data from a host TCP client to `10.0.0.2:9000`. This example waits five seconds before reading, then reads up to 1024 bytes every 20 milliseconds. Its output shows the receive buffer filling and the available window shrinking. Use one client per run for this demonstration.

## Troubleshooting

| Symptom | Check |
| :--- | :--- |
| Opening `/dev/net/tun` fails | Confirm that the Linux environment provides the TUN device |
| `TUNSETIFF` reports a permission error | Check interface ownership or run with suitable privileges |
| `TUNSETIFF` reports a busy device | Stop the other program using the same interface |
| A client waits without connecting | Check that `tun0` is up, the route is correct, and the server is listening |
| The host answers instead of ipact | Confirm that Linux has only the host address assigned |
| Connections fail despite the correct route | Check local firewall rules for traffic on `tun0` |
| No PCAP or CSV file appears | Check the output path and whether the selected example supports that setting |

## Cleanup

Stop the programs, then remove the interface created for these examples.

```sh
sudo ip tuntap del dev tun0 mode tun
```

Return to the [README](../README.md).
