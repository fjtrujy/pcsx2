// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include <bit>
#include <chrono>

#include "common/Assertions.h"
#include "common/Console.h"

#ifdef _WIN32
#include "common/RedtapeWindows.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(__POSIX__)
#define SOCKET_ERROR -1
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#endif

#include "TCP_FixedPort.h"
#include "DEV9/PacketReader/IP/TCP/TCP_Packet.h"

using namespace PacketReader;
using namespace PacketReader::IP;
using namespace PacketReader::IP::TCP;

namespace Sessions
{
	TCP_FixedPort::TCP_FixedPort(ConnectionKey parKey, IP_Address parAdapterIP, u16 parPort,
		IP_Address parPs2IP,
		ThreadSafeMap<ConnectionKey, BaseSession*>* parParentConnections,
		ConnectionClosedEventHandler parChildCloseHandler)
		: BaseSession(parKey, parAdapterIP)
		, ps2IP{parPs2IP}
		, parentConnections{parParentConnections}
		, childCloseHandler{std::move(parChildCloseHandler)}
		, port{parPort}
	{
	}

	bool TCP_FixedPort::Init()
	{
		listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (listenSocket == INVALID_SOCKET)
		{
			Console.Error("DEV9: TCP: FixedPort: socket() failed for port %d. Error: %d", port,
#ifdef _WIN32
				WSAGetLastError());
#elif defined(__POSIX__)
				errno);
#endif
			return false;
		}

		// Allow rebinding immediately after a previous run exits.
		constexpr int reuseAddr = 1;
		setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR,
			reinterpret_cast<const char*>(&reuseAddr), sizeof(reuseAddr));

		sockaddr_in endpoint{};
		endpoint.sin_family = AF_INET;
		endpoint.sin_port = htons(port);
		if (adapterIP.integer != 0)
			endpoint.sin_addr = std::bit_cast<in_addr>(adapterIP);
		else
			endpoint.sin_addr.s_addr = htonl(INADDR_ANY);

		if (bind(listenSocket, reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint)) != 0)
		{
			Console.Error("DEV9: TCP: FixedPort: bind() failed for port %d. Error: %d", port,
#ifdef _WIN32
				WSAGetLastError());
#elif defined(__POSIX__)
				errno);
#endif
#ifdef _WIN32
			closesocket(listenSocket);
#elif defined(__POSIX__)
			::close(listenSocket);
#endif
			listenSocket = INVALID_SOCKET;
			return false;
		}

		if (listen(listenSocket, 8) != 0)
		{
			Console.Error("DEV9: TCP: FixedPort: listen() failed for port %d. Error: %d", port,
#ifdef _WIN32
				WSAGetLastError());
#elif defined(__POSIX__)
				errno);
#endif
#ifdef _WIN32
			closesocket(listenSocket);
#elif defined(__POSIX__)
			::close(listenSocket);
#endif
			listenSocket = INVALID_SOCKET;
			return false;
		}

		// Use a non-blocking socket so the accept thread can poll stopThread.
#ifdef _WIN32
		u_long blocking = 1;
		ioctlsocket(listenSocket, FIONBIO, &blocking);
#elif defined(__POSIX__)
		int flags = fcntl(listenSocket, F_GETFL, 0);
		if (flags >= 0)
			fcntl(listenSocket, F_SETFL, flags | O_NONBLOCK);
#endif

		open.store(true);
		acceptThread = std::thread([this]() { AcceptLoop(); });
		return true;
	}

	void TCP_FixedPort::AcceptLoop()
	{
		using namespace std::chrono_literals;

		while (!stopThread.load())
		{
			sockaddr_in clientAddr{};
#ifdef _WIN32
			int clientLen = sizeof(clientAddr);
			SOCKET newSocket = accept(listenSocket, reinterpret_cast<sockaddr*>(&clientAddr), &clientLen);
#elif defined(__POSIX__)
			socklen_t clientLen = sizeof(clientAddr);
			int newSocket = accept(listenSocket, reinterpret_cast<sockaddr*>(&clientAddr), &clientLen);
#endif

			if (newSocket == INVALID_SOCKET)
			{
#ifdef _WIN32
				const int err = WSAGetLastError();
				if (err == WSAEWOULDBLOCK)
#elif defined(__POSIX__)
				const int err = errno;
				if (err == EWOULDBLOCK || err == EAGAIN)
#endif
				{
					std::this_thread::sleep_for(50ms);
					continue;
				}
				Console.Error("DEV9: TCP: FixedPort: accept() error %d on port %d", err, port);
				std::this_thread::sleep_for(200ms);
				continue;
			}

			IP_Address remoteIP{};
			memcpy(&remoteIP, &clientAddr.sin_addr, sizeof(remoteIP));
			const u16 remotePort = ntohs(clientAddr.sin_port);

			// ConnectionKey for an inbound TCP session, keyed off the PS2's
			// outbound packets: ps2Port = its source = our listen port,
			// srvPort = the foreign port = the remote ephemeral.
			ConnectionKey newKey{};
			newKey.ip = remoteIP;
			newKey.protocol = static_cast<u8>(IP_Type::TCP);
			newKey.ps2Port = port;
			newKey.srvPort = remotePort;

			Console.WriteLn("DEV9: TCP: Accepted inbound connection on port %d from %d.%d.%d.%d:%d",
				port, remoteIP.bytes[0], remoteIP.bytes[1], remoteIP.bytes[2], remoteIP.bytes[3],
				remotePort);

			TCP_Session* s = new TCP_Session(newKey, adapterIP);
			s->AddConnectionClosedHandler(childCloseHandler);
			s->destIP = remoteIP;
			s->sourceIP = ps2IP;

			if (!s->InitInbound(newSocket, remotePort, port))
			{
				Console.Error("DEV9: TCP: FixedPort: InitInbound failed for port %d", port);
				delete s;
#ifdef _WIN32
				closesocket(newSocket);
#elif defined(__POSIX__)
				::close(newSocket);
#endif
				continue;
			}

			// Publish only after InitInbound has staged the synthetic SYN, so
			// the recv thread sees a fully-initialised session.
			parentConnections->Add(newKey, s);
		}
	}

	std::optional<ReceivedPayload> TCP_FixedPort::Recv()
	{
		// The fixed port itself never emits packets — its sessions do.
		return std::nullopt;
	}

	bool TCP_FixedPort::Send(IP_Payload* payload)
	{
		// Inbound sessions are addressed directly via the connections map;
		// nothing should land on the fixed port itself.
		pxAssert(false);
		return false;
	}

	void TCP_FixedPort::Reset()
	{
		// No child-session bookkeeping here: the SocketAdapter resets each
		// TCP_Session it owns through the connections map directly.
	}

	TCP_FixedPort::~TCP_FixedPort()
	{
		stopThread.store(true);
		if (listenSocket != INVALID_SOCKET)
		{
			// Closing the listen socket will unblock any in-flight accept().
#ifdef _WIN32
			closesocket(listenSocket);
#elif defined(__POSIX__)
			::close(listenSocket);
#endif
			listenSocket = INVALID_SOCKET;
		}
		if (acceptThread.joinable())
			acceptThread.join();
		open.store(false);
	}
} // namespace Sessions
