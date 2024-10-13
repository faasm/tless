set(OPENCV_BASE_LIBS opencv_core opencv_imgcodecs opencv_imgproc)
set(OPENCV_ML_LIBS opencv_ml z)


faasm_wflow_func(ml-training driver ./driver/function.cpp)
faasm_wflow_func(ml-training partition ./partition/function.cpp)
faasm_wflow_func(ml-training pca ./pca/function.cpp)
faasm_wflow_func(ml-training rf ./rf/function.cpp)

target_link_libraries(ml-training_pca ${OPENCV_BASE_LIBS})
target_link_libraries(ml-training_rf ${OPENCV_BASE_LIBS} ${OPENCV_ML_LIBS})
