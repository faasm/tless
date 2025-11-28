// time_breakdown.hpp
#pragma once

#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace utils {
class TimeBreakdown {
  public:
    using clock = std::chrono::steady_clock;
    using time_point = clock::time_point;
    using duration = clock::duration;

    explicit TimeBreakdown(std::string name,
                           std::ostream& os = std::cerr)
        : name_(std::move(name)), os_(os)
    {
        checkpoints_.push_back({"<start>", clock::now()});
    }

    // Mark a checkpoint with a label.
    void checkpoint(const std::string& label) {
        checkpoints_.push_back({label, clock::now()});
    }

    ~TimeBreakdown() {
        if (checkpoints_.empty()) return;

        const time_point end = clock::now();

        // Compute label width for pretty alignment
        size_t max_label = 0;
        for (const auto& cp : checkpoints_) {
            max_label = std::max(max_label, cp.label.size());
        }

        os_ << "\n=== Time Breakdown: " << name_ << " ===\n";
        os_ << std::left;

        time_point prev = checkpoints_.front().tp;
        double total_ms = 0.0;

        for (size_t i = 1; i < checkpoints_.size(); ++i) {
            const auto& cp = checkpoints_[i];
            double ms = to_ms(cp.tp - prev);
            total_ms += ms;

            os_ << "  • "
                << std::setw(max_label) << cp.label
                << " : "
                << std::setw(10) << std::fixed << std::setprecision(3)
                << ms << " ms\n";

            prev = cp.tp;
        }

        // Tail segment: last → destruction
        double tail_ms = to_ms(end - prev);
        total_ms += tail_ms;

        os_ << "  • "
            << std::setw(max_label) << "<tail>"
            << " : "
            << std::setw(10) << std::fixed << std::setprecision(3)
            << tail_ms << " ms\n";

        // Summary
        os_ << "-----------------------------------------\n";
        os_ << "  Total time: "
            << std::fixed << std::setprecision(3)
            << total_ms << " ms\n";
        os_ << "=========================================\n\n";
    }

private:
    struct Checkpoint {
        std::string label;
        time_point tp;
    };

    static double to_ms(duration d) {
        return std::chrono::duration<double, std::milli>(d).count();
    }

    std::string name_;
    std::ostream& os_;
    std::vector<Checkpoint> checkpoints_;
};
} // namespace accless::utils
