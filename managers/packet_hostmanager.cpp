#include "packet_hostmanager.h"
#include "usermanager.h"
#include "serverconsole.h"

Packet_HostManager packet_HostManager;

void Packet_HostManager::ParsePacket_Host(TCPConnection::Packet::pointer packet) {
	if (packet == NULL) {
		return;
	}

	auto connection = packet->GetConnection();
	if (connection == NULL) {
		return;
	}

	User* user = userManager.GetUserByConnection(connection);
	if (!userManager.IsUserLoggedIn(user)) {
		serverConsole.Print(PrefixType::Warn, format("[ Packet_HostManager ] Client ({}) has sent Packet_Host, but it's not logged in!\n", connection->GetIPAddress()));
		return;
	}

	serverConsole.Print(PrefixType::Info, format("[ Packet_HostManager ] Parsing Packet_Host from user ({})\n", user->GetUserLogName()));

	unsigned char type = packet->ReadUInt8();

	switch (type) {
		default: {
			serverConsole.Print(PrefixType::Warn, format("[ Packet_HostManager ] User ({}) has sent unregistered Packet_Host type {}!\n", user->GetUserLogName(), type));
			break;
		}
	}
}

void Packet_HostManager::SendPacket_Host_StartGame(User* user) {
	if (user == NULL) {
		return;
	}

	auto connection = user->GetConnection();
	if (connection == NULL) {
		return;
	}

	auto packet = TCPConnection::Packet::Create(PacketSource::Server, connection, { (unsigned char)PacketID::Host });
	if (packet == NULL) {
		return;
	}

	packet->WriteUInt8(Packet_HostType::StartGame);
	packet->WriteUInt32_LE(user->GetUserID());

	packet->Send();
}

void Packet_HostManager::SendPacket_Host_JoinGame(TCPConnection::pointer connection, unsigned long userID) {
	if (connection == NULL) {
		return;
	}

	auto packet = TCPConnection::Packet::Create(PacketSource::Server, connection, { (unsigned char)PacketID::Host });
	if (packet == NULL) {
		return;
	}

	packet->WriteUInt8(Packet_HostType::JoinGame);
	packet->WriteUInt32_LE(userID);

	packet->Send();
}