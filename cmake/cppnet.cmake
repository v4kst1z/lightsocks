include(ExternalProject)

set(CPPNET_ROOT          ${PROJECT_SOURCE_DIR}/thirdparty/CppNet/install)
set(CPPNET_DOWNLOAD_DIR  ${PROJECT_SOURCE_DIR}/thirdparty/CppNet/download)
set(CPPNET_SRC           ${PROJECT_SOURCE_DIR}/thirdparty/CppNet/src)

set(CPPNET_LIB_DIR       ${CPPNET_ROOT}/lib)
set(CPPNET_INCLUDE_DIR   ${CPPNET_ROOT}/include)

set(CPPNET_CONFIGURE     cd ${CPPNET_SRC}/ && mkdir build && cd build && cmake .. -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug)
set(CPPNET_MAKE          cd ${CPPNET_SRC}/build && make )
set(CPPNET_INSTALL       cd ${CPPNET_SRC}/build && sudo make install)


ExternalProject_Add(CppNet 
  GIT_REPOSITORY "https://github.com/v4kst1z/CppNet.git"
  GIT_TAG "main"
  SOURCE_DIR ${CPPNET_SRC}
  DOWNLOAD_DIR ${CPPNET_DOWNLOAD_DIR}
  PREFIX  ${CPPNET_ROOT}
  CONFIGURE_COMMAND ${CPPNET_CONFIGURE} -DCMAKE_INSTALL_PREFIX=${CPPNET_ROOT}
  BUILD_COMMAND ${CPPNET_MAKE}
  INSTALL_COMMAND ${CPPNET_INSTALL} install
)

