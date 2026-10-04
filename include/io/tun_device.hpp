#pragma once
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>

class TunDevice {

public:
	explicit TunDevice(const std::string& name) {
		fd_ = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
		if (fd_ < 0) {
			throw std::system_error(errno, std::generic_category(), "open /dev/net/tun");
		}

		ifreq ifr{};
		ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
		std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
		if(::ioctl(fd_, TUNSETIFF, &ifr) < 0) {
			int e = errno;
			::close(fd_);
			throw std::system_error(e, std::generic_category(), "icotl TUNSETIFF");
		}
		name_ = ifr.ifr_name;
	}

	~TunDevice() {
		 if (fd_ >= 0) {
			::close(fd_); 
		}
	}

	TunDevice(const TunDevice&) = delete;
	TunDevice& operator=(const TunDevice&) = delete;
	TunDevice(TunDevice&& o) noexcept : fd_(o.fd_), name_(std::move(o.name_)) { o.fd_ = -1; }

	ssize_t read_packet(std::span<uint8_t> buf) {
		return ::read(fd_, buf.data(), buf.size());
	}

	ssize_t write_packet(std::span<const uint8_t> pkt) {
		return ::write(fd_, pkt.data(), pkt.size());
	}

	int fd() const { return fd_; }
	const std::string& name() const { return name_; }

private:
	int fd_ = -1;
	std::string name_;
};
