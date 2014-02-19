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


#include "maidsafe/detail/session_getter.h"

namespace maidsafe {

namespace detail {


SessionGetter::SessionGetter(const BootstrapInfo& bootstrap_info)
    : asio_service_(2),
      network_health_mutex_(),
      network_health_condition_variable_(),
      network_health_(-1),
      routing_(NodeId(NodeId::kRandomId)),
      data_getter_(asio_service_, routing_) {
  InitRouting(bootstrap_info);  // FIXME need to update routing to get bootstrap endpoints along with public keys
}



void SessionGetter::InitRouting(const BootstrapInfo& bootstrap_info) {
  routing::Functors functors(InitialiseRoutingCallbacks());
  // BEFORE_RELEASE temp work around, need to update routing to take bootstrap_info
  std::vector<boost::asio::ip::udp::endpoint> peer_endpoints;
  for (const auto& i : bootstrap_info)
    peer_endpoints.push_back(i.first);
  routing_.Join(functors, peer_endpoints);
// FIXME discuss this
  std::unique_lock<std::mutex> lock(network_health_mutex_);
#ifdef TESTING
  if (!network_health_condition_variable_.wait_for(lock, std::chrono::minutes(5), [this] {
         return network_health_ >= 100;  // FIXME need parameter here ?
       }))
    BOOST_THROW_EXCEPTION(MakeError(VaultErrors::failed_to_join_network));
#else
  network_health_condition_variable_.wait(
      lock, [this] { return network_health_ >= detail::Parameters::kMinNetworkHealth; });
#endif
}

routing::Functors SessionGetter::InitialiseRoutingCallbacks() {
  routing::Functors functors;
  functors.typed_message_and_caching.single_to_single.message_received = [this](
      const routing::SingleToSingleMessage& message) { data_getter_.HandleMessage(message); };  // NOLINT
  functors.typed_message_and_caching.group_to_single.message_received = [this](
      const routing::GroupToSingleMessage& message) { data_getter_.HandleMessage(message); };  // NOLINT

  functors.network_status = [this](const int&
                                   network_health) { OnNetworkStatusChange(network_health); };  // NOLINT
  functors.matrix_changed = [this](std::shared_ptr<routing::MatrixChange> /*matrix_change*/) {};
  functors.request_public_key = [this](
    const NodeId& /*node_id*/,
    const routing::GivePublicKeyFunctor& /*give_key*/) {
    // FIXME
  };

  // Unused  TODO move to utility function (fix routing asserts for clients)
//  functors.typed_message_and_caching.single_to_group.message_received = [this](
//      const routing::SingleToGroupMessage& /*message*/) {};  // NOLINT
//  functors.typed_message_and_caching.group_to_group.message_received = [this](
//      const routing::GroupToGroupMessage& /*message*/) {};  // NOLINT
//  functors.typed_message_and_caching.single_to_group_relay.message_received = [this](
//      const routing::SingleToGroupRelayMessage& /*message*/) {};  // NOLINT
//  functors.typed_message_and_caching.single_to_single.get_cache_data = [this](
//      const routing::SingleToSingleMessage& /*message*/) {};  // NOLINT
//  functors.typed_message_and_caching.single_to_group.get_cache_data = [this](
//      const routing::SingleToGroupMessage& /*message*/) {};  // NOLINT
//  functors.typed_message_and_caching.group_to_single.get_cache_data = [this](
//      const routing::GroupToSingleMessage& /*message*/) {};  // NOLINT
//  functors.typed_message_and_caching.group_to_group.get_cache_data = [this](
//      const routing::GroupToGroupMessage& /*message*/) {};  // NOLINT
//  functors.typed_message_and_caching.single_to_single.put_cache_data = [this](
//      const routing::SingleToSingleMessage& /*message*/) {};  // NOLINT
//  functors.typed_message_and_caching.single_to_group.put_cache_data = [this](
//      const routing::SingleToGroupMessage& /*message*/) {};  // NOLINT
//  functors.typed_message_and_caching.group_to_single.put_cache_data = [this](
//      const routing::GroupToSingleMessage& /*message*/) {};  // NOLINT
//  functors.typed_message_and_caching.group_to_group.put_cache_data = [this](
//      const routing::GroupToGroupMessage& /*message*/) {};  // NOLINT
//  functors.new_bootstrap_endpoint = [this](
//      const boost::asio::ip::udp::endpoint& /*endpoint*/) {};  // NOLINT
  return functors;
}


void SessionGetter::OnNetworkStatusChange(int network_health) {
  asio_service_.service().post([=] { DoOnNetworkStatusChange(network_health); });
}

void SessionGetter::DoOnNetworkStatusChange(int network_health) {
  if (network_health >= 0) {
    if (network_health >= network_health_)
      LOG(kVerbose) << "Init - " << DebugId(routing_.kNodeId()) << " - Network health is "
                    << network_health << "% (was " << network_health_ << "%)";
    else
      LOG(kWarning) << "Init - " << DebugId(routing_.kNodeId()) << " - Network health is "
                    << network_health << "% (was " << network_health_ << "%)";
  } else {
    LOG(kWarning) << "Init - " << DebugId(routing_.kNodeId()) << " - Network is down ("
                  << network_health << ")";
  }

  {
    std::lock_guard<std::mutex> lock(network_health_mutex_);
    network_health_ = network_health;
  }
  network_health_condition_variable_.notify_one();
  // TODO(Team) : actions when network is down/up per persona
}

}  // namespace detail

}  // namespace maidsafe
