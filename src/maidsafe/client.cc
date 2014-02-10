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

Client::Client()
    : pimpl_(new Impl()) {}

Client::~Client() {
  SaveSession();
}

// NO THROW
void Client::SaveSession() {
  pimpl_->SaveSession();
}

// immutable data
ImmutableDataFuture Client::Get(const ImmutableData::Name& /*immutable_data_name*/,
  const std::chrono::steady_clock::duration& /*timeout*/) {

}

PutFuture Client::Put(const ImmutableData& /*immutable_data*/,
                      const std::chrono::steady_clock::duration& /*timeout*/) {

}

void Client::Delete(const ImmutableData::Name& /*immutable_data_name*/) {

}

VersionNamesFuture Client::GetVersions(const MutableData::Name& /*mutable_data_name*/,
    const std::chrono::steady_clock::duration& /*timeout*/) {

}

VersionNamesFuture Client::GetBranch(const MutableData::Name& /*mutable_data_name*/,
                             const StructuredDataVersions::VersionName& /*branch_tip*/,
                             const std::chrono::steady_clock::duration& /*timeout*/) {

}

PutFuture Client::PutVersion(const MutableData::Name& /*mutable_data_name*/,
                             const StructuredDataVersions::VersionName& /*old_version_name*/,
                             const StructuredDataVersions::VersionName& /*new_version_name*/) {

}

void Client::DeleteBranchUntilFork(const MutableData::Name& /*mutable_data_name*/,
                                   const StructuredDataVersions::VersionName& /*branch_tip*/) {

}

}  // namespace maidsafe
