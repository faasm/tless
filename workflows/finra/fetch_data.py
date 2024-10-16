# Code inspired from:
# https://github.com/ProjectMitosisOS/dmerge-eurosys24-ae/blob/artifact-eurosys24/exp/finra/data_fetcher.py

from pandas import concat as pd_concat
from os import makedirs
from os.path import dirname, exists, join, realpath
from yfinance import Ticker

PROJ_ROOT = dirname(dirname(dirname(realpath(__file__))))
DATASETS_DIR = join(PROJ_ROOT, "datasets")
FINRA_DATA_DIR = join(DATASETS_DIR, "finra")


def fetch_data():
    if not exists(DATASETS_DIR):
        makedirs(DATASETS_DIR)

    if not exists(FINRA_DATA_DIR):
        makedirs(FINRA_DATA_DIR)

    data_file = join(FINRA_DATA_DIR, "yfinance.csv")

    # ticker symbol lookup in https://finance.yahoo.com/lookup
    tickers = [
        'GOOG', 'AMZN', 'MSFT', 'DRUG', 'AB',
        # 'ABC', 'ABCB', 'AAPL', 'NFLX', 'CS',
        # 'CAMZX', 'AMUB', 'MLPR', 'AMZA', 'AMJ',
        # 'PCAR', 'PEP', 'BAC', 'NVDA', 'TSLA',
        # 'META', 'TSM', 'UNH', 'XOM', 'JNJ',
        # 'WMT', 'JPM', 'PG', 'MA', 'NVO',
        # 'LLY', 'HD', 'MRK', 'ABBV', 'KO', 'AVGO'
    ]
    dfs = []

    for ticker in tickers:
        tickerObj = Ticker(ticker)
        data = tickerObj.history(period="max")
        data["Ticker"] = ticker
        dfs.append(data)

    result = pd_concat(dfs)
    result.to_csv(data_file, index=True)


if __name__ == "__main__":
    fetch_data()
