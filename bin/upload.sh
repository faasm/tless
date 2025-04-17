faasmctl upload finra driver ../tless/workflows/build-wasm/finra/finra_driver.wasm
faasmctl upload finra audit ../tless/workflows/build-wasm/finra/finra_audit.wasm
faasmctl upload finra fetch-public ../tless/workflows/build-wasm/finra/finra_fetch-public.wasm
faasmctl upload finra fetch-private ../tless/workflows/build-wasm/finra/finra_fetch-private.wasm
faasmctl upload finra merge ../tless/workflows/build-wasm/finra/finra_merge.wasm

faasmctl upload word-count reducer ../tless/workflows/build-wasm/word-count/word-count_reducer.wasm
faasmctl upload word-count splitter ../tless/workflows/build-wasm/word-count/word-count_splitter.wasm
faasmctl upload word-count driver ../tless/workflows/build-wasm/word-count/word-count_driver.wasm
faasmctl upload word-count mapper ../tless/workflows/build-wasm/word-count/word-count_mapper.wasm

faasmctl upload ml-training driver ../tless/workflows/build-wasm/ml-training/ml-training_driver.wasm
faasmctl upload ml-training pca ../tless/workflows/build-wasm/ml-training/ml-training_pca.wasm
faasmctl upload ml-training validation ../tless/workflows/build-wasm/ml-training/ml-training_validation.wasm
faasmctl upload ml-training partition ../tless/workflows/build-wasm/ml-training/ml-training_partition.wasm
faasmctl upload ml-training rf ../tless/workflows/build-wasm/ml-training/ml-training_rf.wasm

faasmctl upload ml-inference load ../tless/workflows/build-wasm/ml-inference/ml-inference_load.wasm
faasmctl upload ml-inference partition ../tless/workflows/build-wasm/ml-inference/ml-inference_partition.wasm
faasmctl upload ml-inference driver ../tless/workflows/build-wasm/ml-inference/ml-inference_driver.wasm
faasmctl upload ml-inference predict ../tless/workflows/build-wasm/ml-inference/ml-inference_predict.wasm

