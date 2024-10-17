set(OPENCV_BASE_LIBS opencv_core opencv_imgcodecs opencv_imgproc z)
set(OPENCV_ML_LIBS opencv_ml)

faasm_wflow_func(ml-training driver ./driver/function.cpp)
faasm_wflow_func(ml-training partition ./partition/function.cpp)
faasm_wflow_func(ml-training pca ./pca/function.cpp)
faasm_wflow_func(ml-training rf ./rf/function.cpp)
faasm_wflow_func(ml-training validation ./validation/function.cpp)

target_link_libraries(ml-training_pca ${OPENCV_BASE_LIBS})
target_link_libraries(ml-training_rf ${OPENCV_BASE_LIBS} ${OPENCV_ML_LIBS})

if (NOT CMAKE_SYSTEM_NAME STREQUAL "WASI")
    #$ find_package(ZLIB REQUIRED)
    target_link_libraries(ml-training_pca
        /usr/local/lib/opencv2/libopencv_core.a
        z
    )

    target_link_libraries(ml-training_rf
        /usr/local/lib/opencv2/libopencv_ml.a
        /usr/local/lib/opencv2/libopencv_core.a
        z
    )

    target_link_directories(ml-training_pca PRIVATE /usr/local/lib/opencv2)
    target_link_directories(ml-training_rf PRIVATE /usr/local/lib/opencv2)
endif ()

