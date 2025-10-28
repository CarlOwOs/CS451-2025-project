// C++ standard library
#include <chrono>
#include <condition_variable>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

// POSIX / Linux
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <cerrno>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <endian.h>

// Course-provided
#include "parser.hpp"
#include "hello.h"

// Simple Perfect Link implementation built entirely in this file.

namespace {

// Thread-safe output file handle used by signal handler.
std::ofstream g_outputFile;
std::mutex g_outputMutex;

// Forward declaration for clean shutdown from signal handler.
class PerfectLink;
PerfectLink* g_pl = nullptr;

// Network header definition for DATA and ACK frames.
// Packed to avoid padding; all fields are network byte order on the wire.
#pragma pack(push, 1)
struct WireHeader {
  uint8_t version;     // must be 1
  uint8_t msgType;     // 0 = DATA, 1 = ACK
  uint32_t senderId;   // id of the sender
  uint64_t messageId;  // unique per sender
  uint16_t payloadLen; // 0 for ACK
};
#pragma pack(pop)

enum : uint8_t { MSG_DATA = 0, MSG_ACK = 1 };

static WireHeader makeHeader(uint32_t senderId, uint64_t messageId, uint16_t payloadLen, uint8_t type) {
  WireHeader h{};
  h.version = 1;
  h.msgType = type;
  h.senderId = htonl(senderId);
  h.messageId = htobe64(messageId);
  h.payloadLen = htons(payloadLen);
  return h;
}

static bool parseHeader(const void* buf, size_t len, WireHeader& out) {
  if (len < sizeof(WireHeader)) return false;
  std::memcpy(&out, buf, sizeof(WireHeader));
  if (out.version != 1) return false;
  return true;
}

class PerfectLink {
 public:
  PerfectLink(uint32_t selfId, in_addr_t bindIp, in_port_t bindPort)
      : selfId_(selfId), running_(false), sockfd_(-1) {
    std::memset(&selfAddr_, 0, sizeof(selfAddr_));
    selfAddr_.sin_family = AF_INET;
    selfAddr_.sin_addr.s_addr = bindIp;
    selfAddr_.sin_port = bindPort;
  }

  ~PerfectLink() { stop(); }

  void setDeliverCallback(std::function<void(uint32_t, const std::string&)> cb) {
    deliverCb_ = std::move(cb);
  }

  bool start() {
    if (running_) return true;
    sockfd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd_ < 0) {
      perror("socket");
      return false;
    }
    int yes = 1;
    setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if (::bind(sockfd_, reinterpret_cast<const sockaddr*>(&selfAddr_), sizeof(selfAddr_)) < 0) {
      perror("bind");
      ::close(sockfd_);
      sockfd_ = -1;
      return false;
    }
    running_ = true;
    recvThread_ = std::thread([this] { this->recvLoop(); });
    timerThread_ = std::thread([this] { this->timerLoop(); });
    return true;
  }

  void stop() {
    if (!running_) return;
    running_ = false;
    cv_.notify_all();
    if (sockfd_ >= 0) {
      ::shutdown(sockfd_, SHUT_RD);
    }
    if (recvThread_.joinable()) recvThread_.join();
    if (timerThread_.joinable()) timerThread_.join();
    if (sockfd_ >= 0) {
      ::close(sockfd_);
      sockfd_ = -1;
    }
  }

  // Send a message to a destination. Payload should be reasonably small (<= 1200 bytes).
  uint64_t send(const sockaddr_in& dest, const std::string& payload) {
    const uint64_t msgId = ++nextMsgId_;
    WireHeader h = makeHeader(selfId_, msgId, static_cast<uint16_t>(payload.size()), MSG_DATA);

    std::string frame;
    frame.resize(sizeof(WireHeader) + payload.size());
    std::memcpy(frame.data(), &h, sizeof(WireHeader));
    if (!payload.empty()) std::memcpy(frame.data() + sizeof(WireHeader), payload.data(), payload.size());

    {
      std::lock_guard<std::mutex> lk(mu_);
      Pending p{};
      p.dest = dest;
      p.payload = payload;
      p.messageId = msgId;
      p.next = std::chrono::steady_clock::now();
      p.rto = std::chrono::milliseconds(200);
      p.sendCount = 0;
      unacked_.emplace(msgId, std::move(p));
      frames_[msgId] = std::move(frame);
    }
    cv_.notify_all();
    return msgId;
  }

 private:
  struct Pending {
    sockaddr_in dest{};
    std::string payload;
    uint64_t messageId{0};
    std::chrono::steady_clock::time_point next{};
    std::chrono::milliseconds rto{200};
    size_t sendCount{0};
  };

  void recvLoop() {
    std::vector<char> buf(2048);
    while (running_) {
      sockaddr_in from{};
      socklen_t flen = sizeof(from);
      ssize_t n = ::recvfrom(sockfd_, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr*>(&from), &flen);
      if (n < 0) {
        if (errno == EINTR) continue;
        break;
      }
      if (n < static_cast<ssize_t>(sizeof(WireHeader))) continue;

      WireHeader wh{};
      if (!parseHeader(buf.data(), static_cast<size_t>(n), wh)) continue;

      const uint8_t type = wh.msgType;
      const uint32_t senderId = ntohl(wh.senderId);
      const uint64_t msgId = be64toh(wh.messageId);
      const uint16_t payloadLen = ntohs(wh.payloadLen);

      if (type == MSG_DATA) {
        if (sizeof(WireHeader) + payloadLen > static_cast<size_t>(n)) continue;

        bool firstDelivery = false;
        {
          std::lock_guard<std::mutex> lk(mu_);
          auto& seen = delivered_[senderId];
          if (seen.find(msgId) == seen.end()) {
            seen.insert(msgId);
            firstDelivery = true;
          }
        }

        // Always ACK DATA
        WireHeader ack = makeHeader(selfId_, msgId, 0, MSG_ACK);
        (void)::sendto(sockfd_, &ack, sizeof(ack), 0, reinterpret_cast<sockaddr*>(&from), sizeof(from));

        if (firstDelivery) {
          const char* pl = buf.data() + sizeof(WireHeader);
          std::string payload(pl, pl + payloadLen);
          if (deliverCb_) deliverCb_(senderId, payload);
        }
      } else if (type == MSG_ACK) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = unacked_.find(msgId);
        if (it != unacked_.end()) {
          unacked_.erase(it);
          frames_.erase(msgId);
          cv_.notify_all();
        }
      }
    }
  }

  void timerLoop() {
    std::mt19937 rng{std::random_device{}()};
    while (running_) {
      std::unique_lock<std::mutex> lk(mu_);
      if (unacked_.empty()) {
        cv_.wait(lk, [this]{ return !running_ || !unacked_.empty(); });
        if (!running_) return;
      }
      auto now = std::chrono::steady_clock::now();
      auto nextWake = now + std::chrono::milliseconds(1000);
      for (auto &kv : unacked_) {
        Pending &p = kv.second;
        if (p.next <= now) {
          auto fIt = frames_.find(p.messageId);
          if (fIt == frames_.end()) continue;
          const std::string& frame = fIt->second;
          (void)::sendto(sockfd_, frame.data(), frame.size(), 0, reinterpret_cast<const sockaddr*>(&p.dest), sizeof(p.dest));
          p.sendCount++;
          // Exponential backoff with cap and small jitter
          p.rto = std::min(std::chrono::milliseconds(4000), p.rto * 2);
          std::uniform_int_distribution<int> jitter(-20, 20);
          p.next = std::chrono::steady_clock::now() + p.rto + std::chrono::milliseconds(jitter(rng));
        }
        if (p.next < nextWake) nextWake = p.next;
      }
      cv_.wait_until(lk, nextWake, [this]{ return !running_; });
    }
  }

 private:
  uint32_t selfId_;
  sockaddr_in selfAddr_{};
  std::atomic<bool> running_;
  int sockfd_;

  std::function<void(uint32_t, const std::string&)> deliverCb_;

  std::thread recvThread_;
  std::thread timerThread_;

  std::mutex mu_;
  std::condition_variable cv_;

  std::unordered_map<uint64_t, Pending> unacked_;
  std::unordered_map<uint64_t, std::string> frames_;
  std::unordered_map<uint32_t, std::unordered_set<uint64_t>> delivered_;
  std::atomic<uint64_t> nextMsgId_{0};
};

static void stop(int) {
  signal(SIGTERM, SIG_DFL);
  signal(SIGINT, SIG_DFL);
  if (g_pl) g_pl->stop();
  {
    std::lock_guard<std::mutex> lk(g_outputMutex);
    if (g_outputFile.is_open()) {
      g_outputFile.flush();
      g_outputFile.close();
    }
  }
  exit(0);
}

} // namespace

int main(int argc, char **argv) {
  signal(SIGTERM, stop);
  signal(SIGINT, stop);

  Parser parser(argc, argv);
  parser.parse();

  hello();
  std::cout << std::endl;

  std::cout << "My PID: " << getpid() << "\n";
  std::cout << "From a new terminal type `kill -SIGINT " << getpid() << "` or `kill -SIGTERM "
            << getpid() << "` to stop processing packets\n\n";

  std::cout << "My ID: " << parser.id() << "\n\n";

  std::cout << "List of resolved hosts is:\n";
  std::cout << "==========================\n";
  auto hosts = parser.hosts();
  for (auto &host : hosts) {
    std::cout << host.id << "\n";
    std::cout << "Human-readable IP: " << host.ipReadable() << "\n";
    std::cout << "Machine-readable IP: " << host.ip << "\n";
    std::cout << "Human-readbale Port: " << host.portReadable() << "\n";
    std::cout << "Machine-readbale Port: " << host.port << "\n";
    std::cout << "\n";
  }
  std::cout << "\n";

  std::cout << "Path to output:\n";
  std::cout << "===============\n";
  std::cout << parser.outputPath() << "\n\n";

  std::cout << "Path to config:\n";
  std::cout << "===============\n";
  std::cout << parser.configPath() << "\n\n";

  // Open output file for logs (b and d lines)
  {
    std::lock_guard<std::mutex> lk(g_outputMutex);
    g_outputFile.open(parser.outputPath());
  }

  // Read simple config: numberOfMessages and receiverId (if provided)
  unsigned long numberOfMessages = 0;
  unsigned long receiverId = 0;
  {
    std::ifstream cfg(parser.configPath());
    if (cfg.is_open()) {
      cfg >> numberOfMessages >> receiverId;
      cfg.close();
    }
  }

  // Resolve my host and receiver host
  std::string init_ip = "127.0.0.1";
  Parser::Host selfHost(0UL, init_ip, static_cast<unsigned short>(0));
  Parser::Host recvHost(0UL, init_ip, static_cast<unsigned short>(0));
  for (auto &h : hosts) {
    if (h.id == parser.id()) selfHost = h;
    if (h.id == receiverId) recvHost = h;
  }

  PerfectLink pl(static_cast<uint32_t>(parser.id()), selfHost.ip, selfHost.port);
  g_pl = &pl;

  // Delivery callback: log lines "d sender message" as required
  pl.setDeliverCallback([&](uint32_t senderId, const std::string& payload) {
    // The payload here is a single message string, e.g., "42"
    std::lock_guard<std::mutex> lk(g_outputMutex);
    if (g_outputFile.is_open()) {
      g_outputFile << "d " << senderId << " " << payload << "\n";
      g_outputFile.flush();
    }
  });

  if (!pl.start()) {
    std::cerr << "Failed to start PerfectLink (bind/socket).\n";
    return 1;
  }

  std::cout << "Broadcasting and delivering messages...\n\n";

  // If current process is not the designated receiver, send messages 1..N to receiver
  if (parser.id() != receiverId && numberOfMessages > 0) {
    sockaddr_in dest{};
    std::memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = recvHost.ip;
    dest.sin_port = recvHost.port;

    for (unsigned long i = 1; i <= numberOfMessages; ++i) {
      std::string payload = std::to_string(i);
      {
        std::lock_guard<std::mutex> lk(g_outputMutex);
        if (g_outputFile.is_open()) {
          g_outputFile << "b " << payload << "\n";
        }
      }
      (void)pl.send(dest, payload);
    }
    {
      std::lock_guard<std::mutex> lk(g_outputMutex);
      if (g_outputFile.is_open()) g_outputFile.flush();
    }
  }

  // Wait forever to keep delivering messages
  while (true) {
    std::this_thread::sleep_for(std::chrono::hours(1));
  }

  return 0;
}
