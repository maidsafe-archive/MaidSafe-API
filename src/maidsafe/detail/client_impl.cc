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

namespace maidsafe {

namespace detail {


ClientImpl::ClientImpl(const passport::Maid &maid)
    : asio_service_(2),
      routing_(new routing::Routing(maid)),
      maid_node_nfs_(/*asio_service_, *routing_, passport::PublicPmid::Name()*/) {  // FIXME need pmid hint here
// Start routing object
// FIXME decide on how to get access to bootstrap endpoints

}

ClientImpl::ClientImpl(const passport::Maid& maid, const passport::Anmaid& /*anmaid*/)
    : asio_service_(2),
      routing_(new routing::Routing(maid)),
      maid_node_nfs_(/*asio_service_, *routing_, passport::PublicPmid::Name()*/) {
// Call create account
// throw on failure to create account
}

Client::ImmutableDataFuture ClientImpl::Get(const ImmutableData::Name& /*immutable_data_name*/,
  const std::chrono::steady_clock::duration& /*timeout*/) {
  return Client::ImmutableDataFuture();
}

Client::PutFuture ClientImpl::Put(const ImmutableData& /*immutable_data*/,
                                  const std::chrono::steady_clock::duration& /*timeout*/) {
  return Client::PutFuture();
}

void ClientImpl::Delete(const ImmutableData::Name& /*immutable_data_name*/) {

}

Client::VersionNamesFuture ClientImpl::GetVersions(const MutableData::Name& /*mutable_data_name*/,
    const std::chrono::steady_clock::duration& /*timeout*/) {
  return Client::VersionNamesFuture();
}

Client::VersionNamesFuture ClientImpl::GetBranch(const MutableData::Name& /*mutable_data_name*/,
    const StructuredDataVersions::VersionName& /*branch_tip*/,
    const std::chrono::steady_clock::duration& /*timeout*/) {
  return Client::VersionNamesFuture();
}

Client::PutFuture ClientImpl::PutVersion(const MutableData::Name& /*mutable_data_name*/,
    const StructuredDataVersions::VersionName& /*old_version_name*/,
    const StructuredDataVersions::VersionName& /*new_version_name*/) {
  return Client::PutFuture();
}

void ClientImpl::DeleteBranchUntilFork(const MutableData::Name& /*mutable_data_name*/,
                                       const StructuredDataVersions::VersionName& /*branch_tip*/) {

}

}  // namespace detail

}  // namespace maidsafe
