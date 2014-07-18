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
#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"

namespace maidsafe {

namespace {

detail::NetworkType DoGetNetworkType(detail::NetworkType* initialisation_value) {
  static std::mutex mutex;
  static std::unique_ptr<detail::NetworkType> type;
  std::lock_guard<std::mutex> lock{ mutex };
  if (type) {  // Has been initialised
    if (initialisation_value) {
      LOG(kError) << "Can't change network type after it's been initialised.";
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::already_initialised));
    }
    return *type;
  }

  // Needs initialised
  type = maidsafe::make_unique<detail::NetworkType>(
      initialisation_value ? *initialisation_value : detail::NetworkType::kProduction);
  LOG(kInfo) << "Network type has been initialised to '" <<
      (*type == detail::NetworkType::kProduction ? "kProduction'" :
          (*type == detail::NetworkType::kLocal ? "kLocal'" : "kTestnet'"));
  return *type;
}

}  // unnamed namespace

#ifdef TESTING

void UseLocalNetwork() {
  detail::NetworkType type{ detail::NetworkType::kLocal };
  DoGetNetworkType(&type);
}

void UseRemoteTestnet() {
  detail::NetworkType type{ detail::NetworkType::kTestnet };
  DoGetNetworkType(&type);
}

#endif

namespace detail {

NetworkType GetNetworkType() {
  return DoGetNetworkType(nullptr);
}

}  // namespace detail

}  // namespace maidsafe
