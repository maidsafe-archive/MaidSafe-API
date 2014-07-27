/*  Copyright 2014 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include "maidsafe/config.h"

#include "maidsafe/common/error.h"
#include "maidsafe/common/test.h"

namespace maidsafe {

namespace test {

// TEST_CASE("API config", "[API][Config][Unit]") {
//  maidsafe::detail::NetworkType type;
// #if defined(PRODUCTION_NETWORK)
//  const maidsafe::detail::NetworkType kType(maidsafe::detail::NetworkType::kProduction);
// #elif defined(LOCAL_NETWORK)
//  const maidsafe::detail::NetworkType kType(maidsafe::detail::NetworkType::kLocal);
//  CHECK_NOTHROW(UseLocalNetwork());
// #else
//  const maidsafe::detail::NetworkType kType(maidsafe::detail::NetworkType::kTestnet);
//  CHECK_NOTHROW(UseRemoteTestnet());
// #endif
//  CHECK_NOTHROW(type = maidsafe::detail::GetNetworkType());
//  CHECK(type == kType);
//  CHECK_THROWS_AS(UseLocalNetwork(), common_error);
//  CHECK_NOTHROW(type = maidsafe::detail::GetNetworkType());
//  CHECK(type == kType);
//  CHECK_THROWS_AS(UseRemoteTestnet(), common_error);
//  CHECK_NOTHROW(type = maidsafe::detail::GetNetworkType());
//  CHECK(type == kType);
// }

}  // namespace test

}  // namespace maidsafe
