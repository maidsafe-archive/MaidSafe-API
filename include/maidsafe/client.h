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

#include <chrono>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "boost/asio/ip/udp.hpp"
#include "boost/signals2/signal.hpp"
#include "boost/thread/future.hpp"

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/data_types/immutable_data.h"
#include "maidsafe/common/data_types/mutable_data.h"
#include "maidsafe/common/data_types/structured_data_versions.h"

#include "maidsafe/passport/passport.h"
#include "maidsafe/passport/types.h"


#ifndef MAIDSAFE_CLIENT_H_
#define MAIDSAFE_CLIENT_H_

namespace maidsafe {
namespace test {
  class ClientTest_FUNC_RegisterVault_Test;
}

namespace detail { class ClientImpl; }

typedef std::vector<std::pair<boost::asio::ip::udp::endpoint, asymm::PublicKey>> BootstrapInfo;

class Client {
 public:
  typedef boost::future<void> RegisterVaultFuture, UnregisterVaultFuture;
  typedef boost::future<ImmutableData> ImmutableDataFuture;
  typedef boost::future<void> PutFuture, CreateVersionFuture;
  typedef boost::future<std::unique_ptr<StructuredDataVersions::VersionName>> PutVersionFuture;
  typedef boost::future<std::vector<StructuredDataVersions::VersionName>> VersionNamesFuture;

  typedef boost::signals2::signal<void(int32_t)> OnNetworkHealthChange;

  // For already existing accounts
  Client(const passport::Maid& maid, const BootstrapInfo& bootstrap_info);

  // For new accounts
  // throws on failure to create account
  Client(const passport::MaidAndSigner& maid_and_signer, const BootstrapInfo& bootstrap_info);

  ~Client();

  // FIXME Discuss size parameter ??
  RegisterVaultFuture RegisterVault(const passport::Pmid& pmid,
      const std::chrono::steady_clock::duration& timeout = std::chrono::seconds(10));

  OnNetworkHealthChange& network_health_change_signal();

  //========================== Data accessors and mutators =========================================
  // Immutable data
  ImmutableDataFuture Get(
      const ImmutableData::Name& immutable_data_name,
      const std::chrono::steady_clock::duration& timeout = std::chrono::seconds(10));

  PutFuture Put(const ImmutableData& immutable_data,
                const std::chrono::steady_clock::duration& timeout = std::chrono::seconds(10));

  void Delete(const ImmutableData::Name& immutable_data_name);

  // Structured data
  CreateVersionFuture CreateVersionTree(
      const MutableData::Name& mutable_data_name,
      const StructuredDataVersions::VersionName& first_version_name,
      uint32_t max_versions, uint32_t max_branches,
      const std::chrono::steady_clock::duration& timeout = std::chrono::seconds(10));

  VersionNamesFuture GetVersions(
      const MutableData::Name& mutable_data_name,
      const std::chrono::steady_clock::duration& timeout = std::chrono::seconds(10));

  VersionNamesFuture GetBranch(
      const MutableData::Name& mutable_data_name,
      const StructuredDataVersions::VersionName& branch_tip,
      const std::chrono::steady_clock::duration& timeout = std::chrono::seconds(10));

  PutVersionFuture PutVersion(
      const MutableData::Name& mutable_data_name,
      const StructuredDataVersions::VersionName& old_version_name,
      const StructuredDataVersions::VersionName& new_version_name,
      const std::chrono::steady_clock::duration& timeout = std::chrono::seconds(10));

  void DeleteBranchUntilFork(const MutableData::Name& mutable_data_name,
                             const StructuredDataVersions::VersionName& branch_tip);

  friend class test::ClientTest_FUNC_RegisterVault_Test;

 private:
  std::unique_ptr<detail::ClientImpl> pimpl_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_H_
