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

#include "maidsafe/anonymous_session.h"

#include <utility>

#include "maidsafe/common/error.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/anonymous_session.pb.h"

namespace maidsafe {

AnonymousSession::AnonymousSession()
    : passport(maidsafe::make_unique<passport::Passport>(passport::CreateMaidAndSigner())),
      timestamp(), ip(), port(0), unique_user_id(), root_parent_id() {}

AnonymousSession::AnonymousSession(SerialisedType serialised_session,
                                   const authentication::UserCredentials& user_credentials)
    : passport(), timestamp(), ip(), port(0), unique_user_id(), root_parent_id() {
  protobuf::AnonymousSession proto_session;
  if (!proto_session.ParseFromString(serialised_session))
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
  crypto::CipherText encrypted_passport(NonEmptyString(proto_session.serialised_passport()));
  passport = maidsafe::make_unique<passport::Passport>(encrypted_passport, user_credentials);
  timestamp = TimeStampToPtime(proto_session.timestamp());
  ip = boost::asio::ip::address::from_string(proto_session.ip());
  port = static_cast<uint16_t>(proto_session.port());
  if (proto_session.has_unique_user_id())
    unique_user_id = Identity(proto_session.unique_user_id());
  if (proto_session.has_root_parent_id())
    root_parent_id = Identity(proto_session.root_parent_id());
}

AnonymousSession::AnonymousSession(AnonymousSession&& other)
    : passport(std::move(other.passport)),
      timestamp(std::move(other.timestamp)),
      ip(std::move(other.ip)),
      port(std::move(other.port)),
      unique_user_id(std::move(other.unique_user_id)),
      root_parent_id(std::move(other.root_parent_id)) {}

AnonymousSession& AnonymousSession::operator=(AnonymousSession other) {
  swap(*this, other);
  return *this;
}

AnonymousSession::SerialisedType AnonymousSession::Serialise(
    const authentication::UserCredentials& user_credentials) {
  protobuf::AnonymousSession proto_session;
  proto_session.set_serialised_passport(passport->Encrypt(user_credentials)->string());
  proto_session.set_timestamp(GetTimeStamp());
  proto_session.set_ip(ip.to_string());
  proto_session.set_port(port);
  if (unique_user_id.IsInitialised())
    proto_session.set_unique_user_id(unique_user_id.string());
  if (root_parent_id.IsInitialised())
    proto_session.set_root_parent_id(root_parent_id.string());

  timestamp = TimeStampToPtime(proto_session.timestamp());

  return SerialisedType(proto_session.SerializeAsString());
}

void swap(AnonymousSession& lhs, AnonymousSession& rhs) MAIDSAFE_NOEXCEPT {
  using std::swap;
  swap(lhs.passport, rhs.passport);
  swap(lhs.timestamp, rhs.timestamp);
  swap(lhs.ip, rhs.ip);
  swap(lhs.port, rhs.port);
  swap(lhs.unique_user_id, rhs.unique_user_id);
  swap(lhs.root_parent_id, rhs.root_parent_id);
}

}  // namespace maidsafe
