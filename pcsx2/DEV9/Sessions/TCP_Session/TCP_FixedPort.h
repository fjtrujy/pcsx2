// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once
#include <atomic>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>
#ifdef _WIN32
#include <winsock2.h>
#elif defined(__POSIX__)
#define INVALID_SOCKET -1
#include <sys/socket.h>
#endif

#include "DEV9/Sessions/BaseSession.h"
#include "DEV9/ThreadSafeMap.h"
#include "TCP_Session.h"

namespace Sessions
{
	/*
	 * Mirror of UDP_FixedPort for the inbound TCP case.
	 * Owns a host listen() socket bound to a configured port and runs an
	 * accept() thread. On each accepted connection, it creates a TCP_Session
	 * in inbound mode (synthesizing a SYN to the PS2) and registers it in the
	 * SocketAdapter's connections map so the recv/send threads can drive it.
	 *
	 * The lifetime model differs from UDP_FixedPort: child sessions are not
	 * tracked here because once registered in the SocketAdapter's connections
	 * map, the SocketAdapter owns them via its standard close-handler path.
	 * The fixed port itself stays open until the SocketAdapter is destroyed.
	 */
	class TCP_FixedPort : public BaseSession
	{
	private:
		std::atomic<bool> open{false};
		std::atomic<bool> stopThread{false};

#ifdef _WIN32
		SOCKET listenSocket = INVALID_SOCKET;
#elif defined(__POSIX__)
		int listenSocket = INVALID_SOCKET;
#endif

		std::thread acceptThread;

		PacketReader::IP::IP_Address ps2IP;
		ThreadSafeMap<ConnectionKey, BaseSession*>* parentConnections;
		ConnectionClosedEventHandler childCloseHandler;

	public:
		const u16 port = 0;

		TCP_FixedPort(ConnectionKey parKey,
			PacketReader::IP::IP_Address parAdapterIP,
			u16 parPort,
			PacketReader::IP::IP_Address parPs2IP,
			ThreadSafeMap<ConnectionKey, BaseSession*>* parParentConnections,
			ConnectionClosedEventHandler parChildCloseHandler);

		// Returns false on bind/listen failure.
		bool Init();

		virtual std::optional<ReceivedPayload> Recv();
		virtual bool Send(PacketReader::IP::IP_Payload* payload);
		virtual void Reset();

		virtual ~TCP_FixedPort();

	private:
		void AcceptLoop();
	};
} // namespace Sessions
