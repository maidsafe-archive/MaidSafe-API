#==================================================================================================#
#                                                                                                  #
#  Copyright 2014 MaidSafe.net limited                                                             #
#                                                                                                  #
#  This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,        #
#  version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which    #
#  licence you accepted on initial access to the Software (the "Licences").                        #
#                                                                                                  #
#  By contributing code to the MaidSafe Software, or to this project generally, you agree to be    #
#  bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root        #
#  directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available   #
#  at: http://www.maidsafe.net/licenses                                                            #
#                                                                                                  #
#  Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed    #
#  under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF   #
#  ANY KIND, either express or implied.                                                            #
#                                                                                                  #
#  See the Licences for the specific language governing permissions and limitations relating to    #
#  use of the MaidSafe Software.                                                                   #
#                                                                                                  #
#==================================================================================================#


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake_modules/standard_setup.cmake")
  cmake_minimum_required(VERSION 2.8)  # To suppress warning cluttering error message
  set(Msg "\nThis project can currently only be build as part of the MaidSafe super-project.  For")
  set(Msg "${Msg} full details, see https://github.com/maidsafe/MaidSafe/wiki/Build-Instructions\n")
  message(FATAL_ERROR "${Msg}")
endif()

project(api)

include(../../cmake_modules/standard_setup.cmake)


#==================================================================================================#
# Set up all files as GLOBs                                                                        #
#==================================================================================================#
set(ApiSourcesDir ${PROJECT_SOURCE_DIR}/src/maidsafe)
set(ConvenienceHeader ${PROJECT_SOURCE_DIR}/include/maidsafe.h)
source_group("API Convenience Header" FILES ${ConvenienceHeader})
ms_glob_dir(Api ${ApiSourcesDir} "API")
source_group("API Public Files" FILES ${ApiApi})
ms_glob_dir(ApiDetail ${ApiSourcesDir}/detail "API Detail")
source_group("API Detail Public Files" FILES ${ApiDetailApi})
ms_glob_dir(ApiTests ${ApiSourcesDir}/tests "API Tests")

# Check convenience header is up to date
file(STRINGS ${ConvenienceHeader} MaidSafeHeader REGEX "#include")
foreach(IncludeLine ${MaidSafeHeader})
  string(REGEX REPLACE "^#include[ ]*[\"<]([^\">]*)[\">]" "\\1" IncludeFile "${IncludeLine}")
  if(NOT "${IncludeFile}" STREQUAL "${IncludeLine}")  # i.e. regex replace worked
    list(APPEND Headers "${PROJECT_SOURCE_DIR}/include/${IncludeFile}")
  endif()
endforeach()
list(SORT ApiApi)
list(SORT Headers)
if(NOT "${ApiApi}" STREQUAL "${Headers}")
  set(ApiExtras "${ApiApi}")
  list(REMOVE_ITEM ApiExtras ${Headers})
  set(HeaderExtras "${Headers}")
  list(REMOVE_ITEM HeaderExtras ${ApiApi})
  set(Msg "\ninclude/maidsafe.h is not up to date.\n")
  if(ApiExtras)
    set(Msg "${Msg}It is missing #include statements for the following API files:\n")
    foreach(ApiExtra ${ApiExtras})
      string(REPLACE "${PROJECT_SOURCE_DIR}/" "" ApiExtra "${ApiExtra}")
      set(Msg "${Msg}  ${ApiExtra}\n")
    endforeach()
  endif()
  if(HeaderExtras)
    set(Msg "${Msg}It has #include statements for the following non-existent API files:\n")
    foreach(HeaderExtra ${HeaderExtras})
      string(REPLACE "${PROJECT_SOURCE_DIR}/" "" HeaderExtra "${HeaderExtra}")
      set(Msg "${Msg}  ${HeaderExtra}\n")
    endforeach()
  endif()
  message(AUTHOR_WARNING "${Msg}")
endif()


#==================================================================================================#
# Define MaidSafe libraries and executables                                                        #
#==================================================================================================#
ms_add_static_library(maidsafe_api ${ApiAllFiles} ${ApiDetailAllFiles} ${ConvenienceHeader})

target_include_directories(maidsafe_api PUBLIC ${PROJECT_SOURCE_DIR}/include PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(maidsafe_api maidsafe_nfs_client maidsafe_passport maidsafe_encrypt)

if(MaidsafeTesting)
  ms_add_executable(TESTapi "Tests/API" ${ApiTestsAllFiles})
  add_dependencies(TESTapi vault)
  target_include_directories(TESTapi PRIVATE ${PROJECT_SOURCE_DIR}/src)
  target_link_libraries(TESTapi maidsafe_api)
endif()

ms_rename_outdated_built_exes()


#==================================================================================================#
# Export detail                                                                                    #
#==================================================================================================#


#==================================================================================================#
# Set compiler and linker flags                                                                    #
#==================================================================================================#
include(standard_flags)


#==================================================================================================#
# Export API Dependency paths for UI projects                                                      #
#==================================================================================================#


#==================================================================================================#
# Tests                                                                                            #
#==================================================================================================#
if(MaidsafeTesting)
  ms_add_style_test()
  ms_add_gtests(TESTapi)
  ms_add_project_experimental()
  ms_test_summary_output()
endif()
