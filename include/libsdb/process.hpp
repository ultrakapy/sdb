#ifndef SDB_PROCESS_HPP
#define SDB_PROCESS_HPP

#include <filesystem>
#include <memory>
#include <cstdint>

#include <sys/types.h>

#include <libsdb/registers.hpp>

namespace sdb {
  enum class process_state {
    stopped,
    running,
    exited,
    terminated
  };

  enum class procfs_state : char {
    Running        = 'R', // running or runnable
    Sleeping       = 'S', // interruptible sleep
    DiskSleep      = 'D', // uninterruptible sleep (usually IO)
    Stopped        = 'T', // stopped by job control signal
    TracingStop    = 't', // stopped by debugger (ptrace)
    Zombie         = 'Z', // terminated, not reaped
    Dead           = 'X', // dead (should never be seen)
    Wakekill       = 'K', // wakekill (Linux-specific)
    Waking         = 'W', // waking
    Parked         = 'P', // parked (Linux-specific)
    Idle           = 'I'  // idle kernel thread
  };

  struct stop_reason {
    stop_reason(int wait_status);

    process_state reason;
    std::uint8_t info;
  };

  class process {
  public:
    ~process();
    static std::unique_ptr<process> launch(std::filesystem::path path, bool debug = true);
    static std::unique_ptr<process> attach(pid_t pid);

    void resume(int signal = 0);
    stop_reason wait_on_signal();

    process() = delete;
    process(const process&) = delete;
    process& operator=(const process&) = delete;

    pid_t pid() const { return pid_; }
    process_state state() const { return state_; }

    static constexpr char to_char(procfs_state s) noexcept { return static_cast<char>(s); }

    registers& get_registers() { return *registers_; }
    const registers& get_registers() const { return *registers_; }

    void write_user_area(std::size_t offset, std::uint64_t data);

    void write_fprs(const user_fpregs_struct& fprs);
    void write_gprs(const user_regs_struct& gprs);

  private:
    process(pid_t pid, bool terminate_on_end, bool is_attached)
      : pid_(pid), terminate_on_end_(terminate_on_end),
        is_attached_(is_attached), registers_(new registers(*this)) {}

    void read_all_registers();

    pid_t pid_ = 0;
    bool terminate_on_end_ = true;
    process_state state_ = process_state::stopped;
    bool is_attached_ = true;
    std::unique_ptr<registers> registers_;
  };
}

#endif
