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

#ifndef MAIDSAFE_DETAIL_CLIENT_IMPL_H_
#define MAIDSAFE_DETAIL_CLIENT_IMPL_H_


#include "maidsafe/client.h"

#include "maidsafe/routing/routing_api.h"

#include "maidsafe/nfs/client/maid_node_nfs.h"


namespace maidsafe {

namespace test {
  class ClientTest_FUNC_RegisterVault_Test;
}

namespace detail {

class ClientImpl {
 public:
  ClientImpl(const passport::Maid& maid, const BootstrapInfo& bootstrap_info);

  ClientImpl(const passport::MaidAndSigner& maid_and_signer, const BootstrapInfo& bootstrap_info);

  Client::RegisterVaultFuture RegisterVault(const passport::Pmid& pmid,
                                            const std::chrono::steady_clock::duration& timeout);

  Client::OnNetworkHealthChange& network_health_change_signal();

  Client::ImmutableDataFuture Get(const ImmutableData::Name& immutable_data_name,
                                  const std::chrono::steady_clock::duration& timeout);

  Client::PutFuture Put(const ImmutableData& immutable_data,
                        const std::chrono::steady_clock::duration& timeout);

  void Delete(const ImmutableData::Name& immutable_data_name);

  Client::CreateVersionFuture CreateVersionTree(
      const MutableData::Name& mutable_data_name,
      const StructuredDataVersions::VersionName& first_version_name,
      uint32_t max_versions, uint32_t max_branches,
      const std::chrono::steady_clock::duration& timeout);

  Client::VersionNamesFuture GetVersions(const MutableData::Name& mutable_data_name,
                                         const std::chrono::steady_clock::duration& timeout);

  Client::VersionNamesFuture GetBranch(const MutableData::Name& mutable_data_name,
                                       const StructuredDataVersions::VersionName& branch_tip,
                                       const std::chrono::steady_clock::duration& timeout);

  Client::PutVersionFuture PutVersion(const MutableData::Name& mutable_data_name,
                                      const StructuredDataVersions::VersionName& old_version_name,
                                      const StructuredDataVersions::VersionName& new_version_name,
                                      const std::chrono::steady_clock::duration& timeout);

  void DeleteBranchUntilFork(const MutableData::Name& mutable_data_name,
                             const StructuredDataVersions::VersionName& branch_tip);
  friend class test::ClientTest_FUNC_RegisterVault_Test;

 private:
  void InitRouting(const BootstrapInfo& bootstrap_info);
  routing::Functors InitialiseRoutingCallbacks();
  void OnNetworkStatusChange(int network_health);
  void DoOnNetworkStatusChange(int network_health);

  std::mutex network_health_mutex_;
  std::condition_variable network_health_condition_variable_;
  int network_health_;
  Client::OnNetworkHealthChange network_health_change_signal_;
  passport::Maid maid_;
  routing::Routing routing_;
  std::unique_ptr<nfs_client::MaidNodeNfs> maid_node_nfs_;
  nfs::detail::PublicPmidHelper public_pmid_helper_;
  AsioService asio_service_;
};

}  // namespace detail

}  // namespace maidsafe

#endif  // MAIDSAFE_DETAIL_CLIENT_IMPL_H_
