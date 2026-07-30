add_library(plato_client STATIC
        driver_client.cpp
)

target_compile_features(plato_client PUBLIC cxx_std_23)
target_compile_options(plato_client PRIVATE "$<$<CXX_COMPILER_ID:MSVC>:/EHsc>")
target_include_directories(plato_client PUBLIC "${CMAKE_SOURCE_DIR}/include")
target_link_libraries(plato_client PRIVATE ws2_32)

set_target_properties(plato_client PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/out/${CMAKE_BUILD_TYPE}"
)
