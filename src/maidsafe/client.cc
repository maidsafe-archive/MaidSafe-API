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

#include "maidsafe/client.h"
#include "maidsafe/detail/client_impl.h"

namespace maidsafe {

Client::Client(const passport::Maid& maid, const BootstrapInfo& bootstrap_info)
    : pimpl_(new detail::ClientImpl(maid, bootstrap_info)) {}


Client::Client(const passport::MaidAndSigner& maid_and_signer, const BootstrapInfo& bootstrap_info)
    : pimpl_(new detail::ClientImpl(maid_and_signer, bootstrap_info)) {}

Client::~Client() {}

Client::RegisterVaultFuture Client::RegisterVault(
    const passport::Pmid& pmid,
    const std::chrono::steady_clock::duration& timeout) {
  return pimpl_->RegisterVault(pmid, timeout);
}

Client::OnNetworkHealthChange& Client::network_health_change_signal() {
  return pimpl_->network_health_change_signal();
}

//========================== Data accessors and mutators ===========================================
Client::ImmutableDataFuture Client::Get(
    const ImmutableData::Name& immutable_data_name,
    const std::chrono::steady_clock::duration& timeout) {
  return pimpl_->Get(immutable_data_name, timeout);
}

Client::PutFuture Client::Put(const ImmutableData& immutable_data,
                              const std::chrono::steady_clock::duration& timeout) {
  return pimpl_->Put(immutable_data, timeout);
}

void Client::Delete(const ImmutableData::Name& immutable_data_name) {
  pimpl_->Delete(immutable_data_name);
}

Client::CreateVersionFuture Client::CreateVersionTree(
    const MutableData::Name& mutable_data_name,
    const StructuredDataVersions::VersionName& first_version_name,
    uint32_t max_versions, uint32_t max_branches,
    const std::chrono::steady_clock::duration& timeout) {
  return pimpl_->CreateVersionTree(mutable_data_name, first_version_name, max_versions,
                                   max_branches, timeout);
}

Client::VersionNamesFuture Client::GetVersions(
    const MutableData::Name& mutable_data_name,
    const std::chrono::steady_clock::duration& timeout) {
  return pimpl_->GetVersions(mutable_data_name, timeout);
}

Client::VersionNamesFuture Client::GetBranch(
    const MutableData::Name& mutable_data_name,
    const StructuredDataVersions::VersionName& branch_tip,
    const std::chrono::steady_clock::duration& timeout) {
  return pimpl_->GetBranch(mutable_data_name, branch_tip, timeout);
}

Client::PutVersionFuture Client::PutVersion(
    const MutableData::Name& mutable_data_name,
    const StructuredDataVersions::VersionName& old_version_name,
    const StructuredDataVersions::VersionName& new_version_name,
    const std::chrono::steady_clock::duration& timeout) {
  return pimpl_->PutVersion(mutable_data_name, old_version_name, new_version_name, timeout);
}

void Client::DeleteBranchUntilFork(const MutableData::Name& mutable_data_name,
                                   const StructuredDataVersions::VersionName& branch_tip) {
  pimpl_->DeleteBranchUntilFork(mutable_data_name, branch_tip);
}

}  // namespace maidsafe
