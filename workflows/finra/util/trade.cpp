#include "trade.h"

#ifndef __faasm
#include <cmath>
#endif

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace tless::finra {
std::vector<TradeData> loadCSVFromString(const std::string &data) {
    std::vector<TradeData> trades;
    std::istringstream file(data);
    std::string line;

    // Skip header line
    std::getline(file, line);

    while (std::getline(file, line)) {
        std::istringstream linestream(line);
        TradeData trade;
        std::string date;
        std::string ticker;

        std::getline(linestream, date, ',');
        std::strncpy(trade.date, date.c_str(), sizeof(trade.date) - 1);
        trade.date[sizeof(trade.date) - 1] = '\0';

        linestream >> trade.open;
        linestream.ignore(1);
        linestream >> trade.high;
        linestream.ignore(1);
        linestream >> trade.low;
        linestream.ignore(1);
        linestream >> trade.close;
        linestream.ignore(1);
        linestream >> trade.volume;
        linestream.ignore(1);
        linestream >> trade.dividends;
        linestream.ignore(1);
        linestream >> trade.stockSplits;

        std::getline(linestream, ticker, ',');
        std::strncpy(trade.ticker, ticker.c_str(), sizeof(trade.ticker) - 1);
        trade.ticker[sizeof(trade.ticker) - 1] = '\0';

        trades.push_back(trade);
    }

    return trades;
}

std::vector<uint8_t> serializeTrade(const TradeData &trade) {
    std::vector<uint8_t> buffer(sizeof(TradeData));
    std::memcpy(buffer.data(), &trade, sizeof(TradeData));
    return buffer;
}

TradeData deserializeTrade(const std::vector<uint8_t> &buffer) {
    TradeData trade;
    std::memcpy(&trade, buffer.data(), sizeof(TradeData));
    return trade;
}

std::vector<uint8_t>
serializeTradeVector(const std::vector<TradeData> &trades) {
    std::vector<uint8_t> buffer;
    for (const auto &trade : trades) {
        // Serialize each trade and append to buffer
        auto serializedTrade = serializeTrade(trade);
        buffer.insert(buffer.end(), serializedTrade.begin(),
                      serializedTrade.end());
    }
    return buffer;
}

std::vector<TradeData>
deserializeTradeVector(const std::vector<uint8_t> &buffer) {
    std::vector<TradeData> trades;
    size_t tradeSize = sizeof(TradeData);

    for (size_t i = 0; i < buffer.size(); i += tradeSize) {
        // Extract chunk for a single TradeData
        std::vector<uint8_t> tradeBuffer(buffer.begin() + i,
                                         buffer.begin() + i + tradeSize);
        TradeData trade = deserializeTrade(tradeBuffer);
        trades.push_back(trade);
    }

    return trades;
}

std::vector<uint8_t> serializeHolding(const PortfolioHolding &holding) {
    std::vector<uint8_t> buffer(sizeof(PortfolioHolding));
    std::memcpy(buffer.data(), &holding, sizeof(PortfolioHolding));
    return buffer;
}

PortfolioHolding deserializeHolding(const std::vector<uint8_t> &buffer,
                                    size_t offset) {
    PortfolioHolding holding;
    std::memcpy(&holding, buffer.data() + offset, sizeof(PortfolioHolding));
    return holding;
}

std::vector<uint8_t> serializePortfolio(const Portfolio &portfolio) {
    // Calculate total size needed: number of holdings + all holdings' data
    size_t numHoldings = portfolio.holdings.size();
    size_t bufferSize =
        sizeof(numHoldings) + (numHoldings * sizeof(PortfolioHolding));

    // Create a buffer large enough to hold everything
    std::vector<uint8_t> buffer(bufferSize);
    size_t offset = 0;

    // Copy the number of holdings into the buffer
    std::memcpy(buffer.data(), &numHoldings, sizeof(numHoldings));
    offset += sizeof(numHoldings);

    // Copy all holdings into the buffer
    std::memcpy(buffer.data() + offset, portfolio.holdings.data(),
                numHoldings * sizeof(PortfolioHolding));

    return buffer;
}

Portfolio deserializePortfolio(const std::vector<uint8_t> &buffer) {
    Portfolio portfolio;
    size_t offset = 0;

    // Extract the number of holdings from the buffer
    uint64_t numHoldings;
    std::memcpy(&numHoldings, buffer.data(), sizeof(numHoldings));
    offset += sizeof(numHoldings);

    // Resize the portfolio's holdings vector to hold all entries
    portfolio.holdings.resize(numHoldings);

    // Copy all holdings data directly into the vector
    std::memcpy(portfolio.holdings.data(), buffer.data() + offset,
                numHoldings * sizeof(PortfolioHolding));

    return portfolio;
}
} // namespace tless::finra

namespace tless::finra::rules {
bool potentialInsiderTrade(const Portfolio &portfolio,
                           const std::vector<TradeData> &trades,
                           const std::string &tradeDate,
                           double volumeSpikeThreshold,
                           double priceChangeThreshold) {
    for (const auto &holding : portfolio.holdings) {
        for (size_t i = 1; i < trades.size(); ++i) {
            // Check for matching ticker and date proximity
            if (trades[i].ticker == holding.ticker &&
                trades[i - 1].ticker == holding.ticker) {
                // Detect volume spike
                double volumeChange = static_cast<double>(trades[i].volume) /
                                      trades[i - 1].volume;
                // Detect significant price change
                double priceChange =
                    std::fabs(trades[i].close - trades[i - 1].close) /
                    trades[i - 1].close;

                // Rule condition: significant volume spike and price change
                if (volumeChange > volumeSpikeThreshold &&
                    priceChange > priceChangeThreshold) {
                    std::cout
                        << "finra(audit): potential insider trade detected"
                        << std::endl
                        << "finra(audit): for " << holding.ticker << " on date "
                        << tradeDate << std::endl;
                    return true;
                }
            }
        }
    }

    // No insider trades detected
    return false;
}
} // namespace tless::finra::rules
