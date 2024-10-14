set(OPENCV_BASE_LIBS opencv_core opencv_imgcodecs opencv_imgproc)
set(OPENCV_ML_LIBS opencv_ml z)


faasm_wflow_func(ml-inference driver ./driver/function.cpp)
faasm_wflow_func(ml-inference partition ./partition/function.cpp)
faasm_wflow_func(ml-inference load ./load/function.cpp)
faasm_wflow_func(ml-inference predict ./predict/function.cpp)

target_link_libraries(ml-inference_predict ${OPENCV_BASE_LIBS} ${OPENCV_ML_LIBS})
