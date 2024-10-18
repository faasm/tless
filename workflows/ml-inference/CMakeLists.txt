set(OPENCV_BASE_LIBS opencv_core opencv_imgcodecs opencv_imgproc)
set(OPENCV_ML_LIBS opencv_ml z)


faasm_wflow_func(ml-inference driver ./driver/function.cpp)
faasm_wflow_func(ml-inference partition ./partition/function.cpp)
faasm_wflow_func(ml-inference load ./load/function.cpp)
faasm_wflow_func(ml-inference predict ./predict/function.cpp)

target_link_libraries(ml-inference_predict ${OPENCV_BASE_LIBS} ${OPENCV_ML_LIBS})

if (NOT CMAKE_SYSTEM_NAME STREQUAL "WASI")
    #$ find_package(ZLIB REQUIRED)
    target_link_libraries(ml-inference_predict
        /usr/local/lib/opencv2/libopencv_core.a
        z
    )

    target_link_libraries(ml-inference_predict
        /usr/local/lib/opencv2/libopencv_ml.a
        /usr/local/lib/opencv2/libopencv_core.a
        z
    )

    target_link_directories(ml-inference_predict PRIVATE /usr/local/lib/opencv2)
endif ()
