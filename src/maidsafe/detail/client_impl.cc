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

#include "maidsafe/detail/client_impl.h"

#include <string>
#include <vector>

#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"

namespace maidsafe {

namespace detail {

ClientImpl::ClientImpl(const passport::Maid& maid, const BootstrapInfo& bootstrap_info)
    : network_health_mutex_(),
      network_health_condition_variable_(),
      network_health_(-1),
      network_health_change_signal_(),
      maid_(maid),
      routing_(maid_),
      maid_node_nfs_(),  // deferred construction until asio service is created
      public_pmid_helper_(),
      asio_service_(2) {
  passport::PublicPmid::Name pmid_name;  // FIXME
  maid_node_nfs_ =
      maidsafe::make_unique<nfs_client::MaidNodeNfs>(asio_service_, routing_, pmid_name);
  // FIXME need to update routing to get bootstrap endpoints along with public keys
  InitRouting(bootstrap_info);
  LOG(kInfo) << "Routing Initialised";
}

ClientImpl::ClientImpl(const passport::MaidAndSigner& maid_and_signer,
                       const BootstrapInfo& bootstrap_info)
    : network_health_mutex_(),
      network_health_condition_variable_(),
      network_health_(-1),
      network_health_change_signal_(),
      maid_(maid_and_signer.first),
      routing_(maid_),
      maid_node_nfs_(),  // deferred construction until asio service is created
      public_pmid_helper_(),
      asio_service_(2) {
  passport::PublicPmid::Name pmid_name;  // FIXME to be filled in by vault registration
  maid_node_nfs_ =
      maidsafe::make_unique<nfs_client::MaidNodeNfs>(asio_service_, routing_, pmid_name);
  // FIXME need to update routing to get bootstrap endpoints along with public keys
  InitRouting(bootstrap_info);
  LOG(kInfo) << "Routing Initialised";
  passport::PublicMaid public_maid{ maid_ };
  passport::PublicAnmaid public_anmaid{ maid_and_signer.second };
  LOG(kInfo) << "Calling CreateAccount for maid ID:" << DebugId(public_maid.name());
  nfs_vault::AccountCreation account_creation{ public_maid, public_anmaid };
  auto create_account_future = maid_node_nfs_->CreateAccount(account_creation);
  create_account_future.get();
  LOG(kInfo) << " CreateAccount for maid ID:" << DebugId(public_maid.name()) << " succeeded.";
}

Client::RegisterVaultFuture ClientImpl::RegisterVault(
    const passport::Pmid& pmid,
    const std::chrono::steady_clock::duration& /*timeout*/) {
  nfs_vault::PmidRegistration pmid_registration{ maid_, pmid, false };
  // TODO(Fraser#5#): 2014-02-24 - BEFORE_RELEASE - change nfs to take timeout & return correct type
  maid_node_nfs_->RegisterPmid(pmid_registration);
  return Client::RegisterVaultFuture();
}

Client::OnNetworkHealthChange& ClientImpl::network_health_change_signal() {
  return network_health_change_signal_;
}

Client::ImmutableDataFuture ClientImpl::Get(
    const ImmutableData::Name& immutable_data_name,
    const std::chrono::steady_clock::duration& timeout) {
  return maid_node_nfs_->Get(immutable_data_name, timeout);
}

Client::PutFuture ClientImpl::Put(const ImmutableData& immutable_data,
                                  const std::chrono::steady_clock::duration& /*timeout*/) {
  maid_node_nfs_->Put(immutable_data);
  return Client::PutFuture();  // FIXME Need to return future from maid_node_nfs_->Put()
}

void ClientImpl::Delete(const ImmutableData::Name& immutable_data_name) {
  maid_node_nfs_->Delete(immutable_data_name);
}

Client::CreateVersionFuture ClientImpl::CreateVersionTree(
      const MutableData::Name& mutable_data_name,
      const StructuredDataVersions::VersionName& first_version_name,
      uint32_t max_versions, uint32_t max_branches,
      const std::chrono::steady_clock::duration& timeout) {
  // TODO(Fraser#5#): 2014-02-24 - BEFORE_RELEASE - change nfs to take timeout & return correct type
  return maid_node_nfs_->CreateVersionTree(mutable_data_name, first_version_name, max_versions,
                                           max_branches, timeout);
}

Client::VersionNamesFuture ClientImpl::GetVersions(const MutableData::Name& mutable_data_name,
    const std::chrono::steady_clock::duration& timeout) {
  return maid_node_nfs_->GetVersions(mutable_data_name, timeout);
}

Client::VersionNamesFuture ClientImpl::GetBranch(const MutableData::Name& mutable_data_name,
    const StructuredDataVersions::VersionName& branch_tip,
    const std::chrono::steady_clock::duration& timeout) {
  return maid_node_nfs_->GetBranch(mutable_data_name, branch_tip, timeout);
}

Client::PutVersionFuture ClientImpl::PutVersion(const MutableData::Name& mutable_data_name,
    const StructuredDataVersions::VersionName& old_version_name,
    const StructuredDataVersions::VersionName& new_version_name,
    const std::chrono::steady_clock::duration& timeout) {
  return maid_node_nfs_->PutVersion(mutable_data_name, old_version_name, new_version_name, timeout);
}

void ClientImpl::DeleteBranchUntilFork(const MutableData::Name& mutable_data_name,
                                       const StructuredDataVersions::VersionName& branch_tip) {
  return maid_node_nfs_->DeleteBranchUntilFork(mutable_data_name, branch_tip);
}

void ClientImpl::InitRouting(const BootstrapInfo& bootstrap_info) {
  routing::Functors functors(InitialiseRoutingCallbacks());
  // BEFORE_RELEASE temp work around, need to update routing to take bootstrap_info
  std::vector<boost::asio::ip::udp::endpoint> peer_endpoints;
  for (const auto& i : bootstrap_info)
    peer_endpoints.push_back(i.first);
  routing_.Join(functors, peer_endpoints);
  std::unique_lock<std::mutex> lock(network_health_mutex_);
  // FIXME BEFORE_RELEASE discuss this
  // This should behave differently. In case of new maid account, it should timeout
  // For existing clients, should we try infinitly ?
  network_health_condition_variable_.wait(lock, [this] { return network_health_ >= 100; });
}

routing::Functors ClientImpl::InitialiseRoutingCallbacks() {
  routing::Functors functors;
  functors.typed_message_and_caching.single_to_single.message_received =
      [this](const routing::SingleToSingleMessage& message) {
        maid_node_nfs_->HandleMessage(message);
      };

  functors.typed_message_and_caching.group_to_single.message_received =
      [this](const routing::GroupToSingleMessage& message) {
        maid_node_nfs_->HandleMessage(message);
      };

  functors.network_status =
      [this](const int& network_health) { OnNetworkStatusChange(network_health); };
  functors.matrix_changed = [this](std::shared_ptr<routing::MatrixChange> /*matrix_change*/) {};
  functors.request_public_key = [this](const NodeId& node_id,
                                       const routing::GivePublicKeyFunctor& give_key) {
    auto future_key(maid_node_nfs_->Get(passport::PublicPmid::Name{ Identity{ node_id.string() } },
                                        std::chrono::seconds(10)));
    public_pmid_helper_.AddEntry(std::move(future_key), give_key);
  };

  // TODO(Prakash) fix routing asserts for clients so client need not to provide callbacks for all
  // functors
  functors.typed_message_and_caching.single_to_group.message_received =
      [this](const routing::SingleToGroupMessage& /*message*/) {};
  functors.typed_message_and_caching.group_to_group.message_received =
      [this](const routing::GroupToGroupMessage& /*message*/) {};
  functors.typed_message_and_caching.single_to_group_relay.message_received =
      [this](const routing::SingleToGroupRelayMessage& /*message*/) {};
  functors.typed_message_and_caching.single_to_group.put_cache_data =
      [this](const routing::SingleToGroupMessage& /*message*/) {};
  functors.typed_message_and_caching.group_to_single.put_cache_data =
      [this](const routing::GroupToSingleMessage& /*message*/) {};
  functors.typed_message_and_caching.group_to_group.put_cache_data =
      [this](const routing::GroupToGroupMessage& /*message*/) {};
  functors.new_bootstrap_endpoint =
      [this](const boost::asio::ip::udp::endpoint& /*endpoint*/) {};

  return functors;
}

void ClientImpl::OnNetworkStatusChange(int updated_network_health) {
  asio_service_.service().post([=] {
    routing::UpdateNetworkHealth(updated_network_health, network_health_, network_health_mutex_,
                                 network_health_condition_variable_, routing_.kNodeId());
  });
}

}  // namespace detail

}  // namespace maidsafe
