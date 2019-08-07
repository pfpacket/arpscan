#include <iostream>
#include <vector>
#include <chrono>
#include <thread>
#include <cassert>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>

struct arp_hdr {
    __be16      ar_hrd;         /* format of hardware address */
    __be16      ar_pro;         /* format of protocol address */
    unsigned char   ar_hln;     /* length of hardware address */
    unsigned char   ar_pln;     /* length of protocol address */
    __be16      ar_op;          /* ARP opcode (command) */

    struct ether_addr   ar_sha;     /* sender hardware address */
    struct in_addr      ar_sip;     /* sender IP address       */
    struct ether_addr   ar_tha;     /* target hardware address */
    struct in_addr      ar_tip;     /* target IP address       */
} __attribute__((packed));

constexpr auto ethhdr_size = sizeof (struct ethhdr);
constexpr auto arphdr_size = sizeof (struct arp_hdr);
constexpr auto arp_packet_size = ethhdr_size + arphdr_size;
constexpr struct ether_addr ether_broadcast = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

[[noreturn]] static void throw_system_error(int err)
{
    throw std::system_error(err, std::system_category());
}

[[noreturn]] void throw_system_error(const std::string& errmsg, int err)
{
    throw std::system_error(err, std::system_category(), errmsg);
}

/*
 * RAII wrapper
 */
template<typename Dtor>
struct raii_guard final {
    raii_guard(const raii_guard&) = delete;
    raii_guard& operator=(const raii_guard&) = delete;
    raii_guard(raii_guard&&) = delete;
    raii_guard& operator=(raii_guard&&) = delete;
    ~raii_guard()
    {
        if (drop) try {
            dtor_();
        } catch (...) {
            /* we must not throw exceptions in dtor */
        }
    }
    Dtor dtor_;
    bool drop = true;
};

template<typename Dtor>
raii_guard<typename std::decay<Dtor>::type> make_raii(Dtor&& dtor)
{
    return { std::forward<Dtor>(dtor), true };
}

class epoller {
public:
    epoller() : epoll_fd_(epoll_create1(EPOLL_CLOEXEC))
    {
        if (epoll_fd_ == -1)
            throw_system_error("epoll_create", errno);
    }

    ~epoller()
    {
        close(epoll_fd_);
    }

    void add(int fd, int events)
    {
        this->ctl(EPOLL_CTL_ADD, fd, events);
    }

    void modify(int fd, int events)
    {
        this->ctl(EPOLL_CTL_MOD, fd, events);
    }

    void remove(int fd)
    {
        this->ctl(EPOLL_CTL_DEL, fd, 0);
    }

    void ctl(int op, int fd, int events)
    {
        struct epoll_event event{0, {0}};
        event.events = events;
        event.data.fd = fd;

        if (epoll_ctl(epoll_fd_, op, fd, &event) == -1)
            throw_system_error("epoll_ctl", errno);
    }

    std::vector<struct epoll_event> wait(int timeout = -1, size_t max_events = 16)
    {
        std::vector<struct epoll_event> events(max_events);

        const int event_num = epoll_wait(epoll_fd_, events.data(), events.size(), timeout);
        if (event_num == -1)
            throw_system_error("epoll_wait", errno);

        events.erase(events.begin() + event_num, events.end());
        return events;
    }

private:
    const int epoll_fd_;

    epoller(const epoller&) = delete;
    epoller& operator=(const epoller&) = delete;
    epoller(epoller &&) = delete;
    epoller& operator=(epoller &&) = delete;
};

class subnet_iterator {
public:
    using value_type = uint32_t;

    subnet_iterator(value_type addr, uint32_t mask)
        : mask_(mask), addr_(addr)
    {
        if (mask_ >= 32)
            throw std::runtime_error("subnet_iterator: mask >= 32");
    }

    value_type host() const {
        return addr_ & this->hostmask();
    }

    value_type address() const {
        return addr_;
    }

    struct in_addr to_in_addr() const {
        return in_addr{htonl(addr_)};
    }

    subnet_iterator end() const {
        return subnet_iterator(addr_ | this->hostmask(), mask_);
    }

    subnet_iterator& operator++() {
        addr_++;
        return *this;
    }

    subnet_iterator operator++(int) {
        auto cloned = *this;
        ++(*this);
        return cloned;
    }

    bool operator==(const subnet_iterator& rhs) const {
        return mask_ == rhs.mask_ && this->host() == rhs.host();
    }

    bool operator!=(const subnet_iterator& rhs) const {
        return !(*this == rhs);
    }

private:
    uint32_t mask_;
    value_type addr_;

    value_type hostmask() const {
        return 0xffffffff >> mask_;
    }
};

static std::string ipaddr_to_string(const struct in_addr addr)
{
    char buf[512];
    if (!inet_ntop(AF_INET, &addr, buf, sizeof (buf)))
        throw_system_error(errno);

    return buf;
}

static std::string ethaddr_to_string(const struct ether_addr *addr)
{
    char buf[512];
    if (!ether_ntoa_r(addr, buf))
        throw_system_error(errno);

    return buf;
}

class arp_scanner {
public:
    arp_scanner(const std::string& ifname) : ifname_(ifname)
    {
        this->init(ifname_);
    }

    ~arp_scanner()
    {
        close(sender_fd_);
        close(recver_fd_);
    }

    void scan(in_addr addr, uint32_t mask)
    {
        std::thread sender([this, addr, mask]() {
            auto raii = make_raii([this]() {
                /* done in an 'atomic' way */
                this->sender_finished_ = 1;
            });

            try {
                this->send_arp_requests(addr, mask);
            } catch (const std::exception& e) {
                std::cerr << "[-] Error: sender: " << e.what() << std::endl;
            }
        });

        auto raii = make_raii([&]() {
            sender.join();
        });

        this->recv_arp_replies(addr, mask);
    }

private:
    void init(const std::string& ifname)
    {
        sender_fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sender_fd_ == -1)
            throw_system_error("socket", errno);

        recver_fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (recver_fd_ == -1)
            throw_system_error("socket", errno);

        ifindex_ = if_nametoindex(ifname.c_str());
        if (ifindex_ == 0)
            throw_system_error(ifname, errno);

        struct sockaddr_ll sll{};
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ARP);
        sll.sll_ifindex = ifindex_;

        if (::bind(recver_fd_, reinterpret_cast<struct sockaddr *>(&sll), sizeof (sll)) == -1)
            throw_system_error("bind", errno);

        this->get_if_info(sender_fd_, ifname);
    }

    void get_if_info(int sockfd, const std::string& ifname)
    {
        struct ifreq ifr;

        ifr.ifr_addr.sa_family = AF_INET;
        std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);

        if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
            throw_system_error(errno);

        std::memcpy(&ifhwaddr_, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);

        if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1)
            throw_system_error(errno);

        ifaddr_ = (reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr))->sin_addr;
    }

    void send_arp_requests(in_addr addr, uint32_t mask)
    {
        std::vector<uint8_t> frame(arp_packet_size);
        auto eth = reinterpret_cast<struct ethhdr *>(frame.data());
        auto arp = reinterpret_cast<struct arp_hdr *>(frame.data() + ethhdr_size);

        auto it = subnet_iterator(ntohl(addr.s_addr), mask);
        auto end = it.end();

        std::cerr << "[*] Starting ARP scan: [" << ipaddr_to_string(addr)
            << ", " << ipaddr_to_string(end.to_in_addr()) << ")" << std::endl;

        for (; it != end; ++it) {
            std::memcpy(&eth->h_source, &ifhwaddr_, ETH_ALEN);
            std::memcpy(&eth->h_dest, &ether_broadcast, ETH_ALEN);
            eth->h_proto = htons(ETH_P_ARP);

            arp->ar_hrd = htons(ARPHRD_ETHER);
            arp->ar_pro = htons(ETHERTYPE_IP);
            arp->ar_hln = ETH_ALEN;
            arp->ar_pln = sizeof (in_addr_t);
            arp->ar_op = htons(ARPOP_REQUEST);

            arp->ar_sha = ifhwaddr_;
            arp->ar_sip = ifaddr_;
            arp->ar_tha = ether_broadcast;
            arp->ar_tip = it.to_in_addr();

            struct sockaddr_ll sll{};
            sll.sll_family = AF_PACKET;
            sll.sll_ifindex = ifindex_;
            sll.sll_halen = ETH_ALEN;
            std::memcpy(&sll.sll_addr, &eth->h_dest, ETH_ALEN);

            if (sendto(sender_fd_, frame.data(), frame.size(), 0,
                        reinterpret_cast<struct sockaddr *>(&sll), sizeof (sll)) == -1)
                throw_system_error("sendto", errno);

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    void recv_arp_replies(in_addr addr, uint32_t mask) const
    {
        const auto end_addr = subnet_iterator(ntohl(addr.s_addr), mask).end();

        epoller poller;
        poller.add(recver_fd_, EPOLLIN | EPOLLERR);

        std::vector<uint8_t> frame(65535);
        struct sockaddr_ll sll{};
        socklen_t socklen = sizeof (sll);

        while (true) {
            const auto events = poller.wait(5000);

            if (events.size() == 0 && sender_finished_)
                break;

            for (const auto event : events) {
                (void) event;

                auto ret = recvfrom(recver_fd_, frame.data(), frame.size(), 0,
                        reinterpret_cast<struct sockaddr *>(&sll), &socklen);
                if (ret == -1)
                    throw_system_error("recvfrom", errno);

                assert(static_cast<size_t>(ret) >= (arp_packet_size));

                auto eth = reinterpret_cast<struct ethhdr *>(frame.data());
                auto arp = reinterpret_cast<struct arp_hdr *>(frame.data() + ethhdr_size);

                struct ether_addr eth_source, eth_dest;
                std::memcpy(&eth_source, eth->h_source, ETH_ALEN);
                std::memcpy(&eth_dest, eth->h_dest, ETH_ALEN);

                if (/*eth_dest == ifhwaddr_ && */
                        arp->ar_hrd == htons(ARPHRD_ETHER) && arp->ar_pro == htons(ETHERTYPE_IP) &&
                        arp->ar_hln == ETH_ALEN && arp->ar_pln == sizeof (in_addr_t) &&
                        arp->ar_op == htons(ARPOP_REPLY) /*&& arp->ar_tha == ifhwaddr_ && arp->ar_tip == ifaddr_*/) {

                    /* make sure the hosts found are in the specified subnet */
                    if (addr.s_addr <= arp->ar_sip.s_addr && arp->ar_sip.s_addr < end_addr.to_in_addr().s_addr)
                        std::cout << "[*] " << ipaddr_to_string(arp->ar_sip)
                            << " is at "<< ethaddr_to_string(&eth_source) << std::endl;
                }
            }
        }
    }

    /*
     * can be accessed as an atomic entity
     */
    volatile sig_atomic_t sender_finished_ = 0;

    /*
     * all the members below are practically read-only and
     *  initialized before spawning a sender thread
     */

    std::string ifname_;
    int sender_fd_;
    int recver_fd_;
    int ifindex_;
    struct ether_addr ifhwaddr_;
    struct in_addr ifaddr_;
};

int main(int argc, char **argv)
{
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " IFNAME IPADDR SUBNETMASK" << std::endl
            << "Detect link-up network interfaces in the specified subnet" << std::endl
            << std::endl
            << "Examples:" << std::endl
            << "  " << argv[0] << " eth0 10.75.0.0 16" << std::endl;
        return EXIT_FAILURE;
    }

    int exit_code = EXIT_SUCCESS;

    try {
        arp_scanner scanner(argv[1]);

        in_addr addr;
        if (!inet_pton(AF_INET, argv[2], &addr))
            throw std::runtime_error("inet_pton: invalid IP address specified");

        auto mask = std::stoul(argv[3]);

        scanner.scan(addr, mask);
    } catch (const std::exception& e) {
        std::cerr << "[-] Error: " << e.what() << std::endl;
        exit_code = EXIT_FAILURE;
    }

    return exit_code;
}
