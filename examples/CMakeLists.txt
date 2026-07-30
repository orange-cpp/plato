add_executable(plato_client_example
        driver_client_example.cpp
)

target_compile_features(plato_client_example PRIVATE cxx_std_23)
target_compile_options(plato_client_example PRIVATE "$<$<CXX_COMPILER_ID:MSVC>:/EHsc>")
target_link_libraries(plato_client_example PRIVATE plato_client)

set_target_properties(plato_client_example PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/out/${CMAKE_BUILD_TYPE}"
)
