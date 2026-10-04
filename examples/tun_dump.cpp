#include <cstdio>
#include <vector>
#include "io/tun_device.hpp"

static void hexdump(const uint8_t* p, size_t n) {
	for (size_t i  = 0; i < n; i+=16) {
		std::printf("%04zx  ", i);
		for (size_t j = 0; j < 16; ++j) {
			if (i + j < n) std::printf("%02x ", p[i+j]);
			else std::printf("    ");
		}

		std::printf(" ");
		for (size_t j = 0; j < 16 && i + j < n; ++j)
			std::printf("%c", (p[i+j] >= 32 && p[i+j] < 127) ? p[i+j] : '.');
		std::printf("\n");
	}
}

int main() {
	TunDevice tun("tun0");
	std::printf("opened %s\n", tun.name().c_str());

	std::vector<uint8_t> buf(65535);
	for (;;) {
		ssize_t n = tun.read_packet(buf);
		if (n < 0) {
			std::perror("read");
			return 1;
		}

		std::printf("--- packet, %zd bytes ---\n", n);
		hexdump(buf.data(), static_cast<size_t>(n));
	}
}
