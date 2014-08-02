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

#ifndef MAIDSAFE_DETAIL_ACCOUNT_GETTER_H_
#define MAIDSAFE_DETAIL_ACCOUNT_GETTER_H_

#include <condition_variable>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "boost/asio/ip/udp.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/routing/api_config.h"
#include "maidsafe/routing/routing_api.h"
#include "maidsafe/nfs/public_pmid_helper.h"
#include "maidsafe/nfs/client/data_getter.h"

namespace maidsafe {

namespace detail {

class AccountHandler;

class AccountGetter {
 public:
  AccountGetter(const AccountGetter&) = delete;
  AccountGetter(AccountGetter&&) = delete;
  AccountGetter& operator=(const AccountGetter&) = delete;
  AccountGetter& operator=(AccountGetter&&) = delete;

  static std::future<std::shared_ptr<AccountGetter>> CreateAccountGetter();
  friend class AccountHandler;

 private:
  AccountGetter();
  void InitRouting();
  routing::Functors InitialiseRoutingCallbacks();
  void OnNetworkStatusChange(int updated_network_health);

  nfs_client::DataGetter& data_getter() { return *data_getter_; }

  std::mutex network_health_mutex_;
  std::condition_variable network_health_condition_variable_;
  int network_health_;
  routing::Routing routing_;
  std::unique_ptr<nfs_client::DataGetter> data_getter_;
  nfs::detail::PublicPmidHelper public_pmid_helper_;
  AsioService asio_service_;
};

}  // namespace detail

}  // namespace maidsafe

#endif  // MAIDSAFE_DETAIL_ACCOUNT_GETTER_H_
