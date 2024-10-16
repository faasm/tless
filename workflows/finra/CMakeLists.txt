add_library(finra_utils ./util/trade.cpp)
target_include_directories(finra_utils PUBLIC ./util)

faasm_wflow_func(finra driver ./driver/function.cpp)
faasm_wflow_func(finra fetch-public ./fetch-public/function.cpp)
faasm_wflow_func(finra fetch-private ./fetch-private/function.cpp)
faasm_wflow_func(finra audit ./audit/function.cpp)
faasm_wflow_func(finra merge ./merge/function.cpp)

target_link_libraries(finra_fetch-public finra_utils)
target_link_libraries(finra_fetch-private finra_utils)
target_link_libraries(finra_audit finra_utils)
