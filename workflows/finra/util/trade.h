#pragma once

#include <cstring>
#include <string>
#include <vector>

struct TradeData {
    char date[25];
    double open;
    double high;
    double low;
    double close;
    uint64_t volume;
    double dividends;
    double stockSplits;
    char ticker[10];
};

struct PortfolioHolding {
    char ticker[10];
    uint64_t quantity;
    double purchasePrice;
};

struct Portfolio {
    std::vector<PortfolioHolding> holdings;
};

namespace tless::finra {
std::vector<TradeData> loadCSVFromString(const std::string &data);

// Trade (de-)serialization
std::vector<uint8_t> serializeTrade(const TradeData &trade);
TradeData deserializeTrade(const std::vector<uint8_t> &buffer);
std::vector<uint8_t> serializeTradeVector(const std::vector<TradeData> &trades);
std::vector<TradeData>
deserializeTradeVector(const std::vector<uint8_t> &buffer);

// Portfolio (de-)serialization
std::vector<uint8_t> serializeHolding(const PortfolioHolding &holding);
PortfolioHolding deserializeHolding(const std::vector<uint8_t> &buffer,
                                    size_t offset);
std::vector<uint8_t> serializePortfolio(const Portfolio &portfolio);
Portfolio deserializePortfolio(const std::vector<uint8_t> &buffer);
} // namespace tless::finra

// Specific audit rules. We only implement one rule, and each parallel function
// runs the same rule. In reality, each function would implement a different
// rule from the FINRA rule book:
// https://www.finra.org/rules-guidance/rulebooks/finra-rules/4000
namespace tless::finra::rules {

// This rule checks if a stock in the private portfolio is sold within a
// specific time window before a significant movent in the public trading
// data, like a sudden increase in trading volume or price. If this is
// detected, we flag it as insider trade
bool potentialInsiderTrade(const Portfolio &portfolio,
                           const std::vector<TradeData> &trades,
                           const std::string &tradeDate,
                           double volumeSpikeThreshold = 1.5,
                           double priceChangeThreshold = 0.05);
} // namespace tless::finra::rules
