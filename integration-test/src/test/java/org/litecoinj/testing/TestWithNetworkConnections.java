/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.litecoinj.testing;

import org.litecoinj.base.ScriptType;
import org.litecoinj.base.Address;
import org.litecoinj.core.BlockChain;
import org.litecoinj.base.Coin;
import org.litecoinj.core.Context;
import org.litecoinj.core.Message;
import org.litecoinj.core.NetworkParameters;
import org.litecoinj.core.Peer;
import org.litecoinj.core.Ping;
import org.litecoinj.core.Pong;
import org.litecoinj.core.Services;
import org.litecoinj.core.VersionAck;
import org.litecoinj.core.VersionMessage;
import org.litecoinj.core.listeners.PreMessageReceivedEventListener;
import org.litecoinj.net.BlockingClient;
import org.litecoinj.net.BlockingClientManager;
import org.litecoinj.net.ClientConnectionManager;
import org.litecoinj.net.NioClient;
import org.litecoinj.net.NioClientManager;
import org.litecoinj.net.NioServer;
import org.litecoinj.net.StreamConnection;
import org.litecoinj.net.StreamConnectionFactory;
import org.litecoinj.params.TestNet3Params;
import org.litecoinj.params.UnitTestParams;
import org.litecoinj.store.BlockStore;
import org.litecoinj.store.MemoryBlockStore;
import org.litecoinj.utils.BriefLogFormatter;
import org.litecoinj.utils.Threading;
import org.litecoinj.wallet.KeyChainGroup;
import org.litecoinj.wallet.Wallet;

import javax.annotation.Nullable;
import javax.net.SocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.time.Duration;
import java.util.Random;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.litecoinj.base.internal.Preconditions.checkArgument;
import static org.litecoinj.base.internal.Preconditions.checkState;

/**
 * Utility class that makes it easy to work with mock NetworkConnections.
 */
public class TestWithNetworkConnections {
    protected static final int TCP_PORT_BASE = 10000 + new Random().nextInt(40000);
    public static final int PEER_SERVERS = 5;

    protected static final NetworkParameters UNITTEST = UnitTestParams.get();
    protected static final NetworkParameters TESTNET = TestNet3Params.get();
    protected BlockStore blockStore;
    protected BlockChain blockChain;
    protected Wallet wallet;
    protected Address address;
    protected SocketAddress socketAddress;

    private NioServer[] peerServers = new NioServer[PEER_SERVERS];
    private final ClientConnectionManager channels;
    protected final BlockingQueue<InboundMessageQueuer> newPeerWriteTargetQueue = new LinkedBlockingQueue<>();

    public enum ClientType {
        NIO_CLIENT_MANAGER,
        BLOCKING_CLIENT_MANAGER,
        NIO_CLIENT,
        BLOCKING_CLIENT
    }
    private final ClientType clientType;
    public TestWithNetworkConnections(ClientType clientType) {
        this.clientType = clientType;
        if (clientType == ClientType.NIO_CLIENT_MANAGER)
            channels = new NioClientManager();
        else if (clientType == ClientType.BLOCKING_CLIENT_MANAGER)
            channels = new BlockingClientManager();
        else
            channels = null;
    }

    public void setUp() throws Exception {
        setUp(new MemoryBlockStore(UNITTEST.getGenesisBlock()));
    }
    
    public void setUp(BlockStore blockStore) throws Exception {
        BriefLogFormatter.init();
        Context.propagate(new Context(100, Coin.ZERO, false, false));
        this.blockStore = blockStore;
        // Allow subclasses to override the wallet object with their own.
        if (wallet == null) {
            // Reduce the number of keys we need to work with to speed up these tests.
            KeyChainGroup kcg = KeyChainGroup.builder(UNITTEST.network()).lookaheadSize(4).lookaheadThreshold(2)
                    .fromRandom(ScriptType.P2PKH).build();
            wallet = new Wallet(UNITTEST.network(), kcg);
            address = wallet.freshReceiveAddress(ScriptType.P2PKH);
        }
        blockChain = new BlockChain(UNITTEST, wallet, blockStore);

        startPeerServers();
        if (clientType == ClientType.NIO_CLIENT_MANAGER || clientType == ClientType.BLOCKING_CLIENT_MANAGER) {
            channels.startAsync();
            channels.awaitRunning();
        }

        socketAddress = new InetSocketAddress(InetAddress.getLoopbackAddress(), 1111);
    }

    protected void startPeerServers() throws IOException {
        for (int i = 0 ; i < PEER_SERVERS ; i++) {
            startPeerServer(i);
        }
    }

    protected void startPeerServer(int i) throws IOException {
        peerServers[i] = new NioServer(new StreamConnectionFactory() {
            @Nullable
            @Override
            public StreamConnection getNewConnection(InetAddress inetAddress, int port) {
                return new InboundMessageQueuer(UNITTEST) {
                    @Override
                    public void connectionClosed() {
                    }

                    @Override
                    public void connectionOpened() {
                        newPeerWriteTargetQueue.offer(this);
                    }
                };
            }
        }, new InetSocketAddress(InetAddress.getLoopbackAddress(), TCP_PORT_BASE + i));
        peerServers[i].startAsync();
        peerServers[i].awaitRunning();
    }

    public void tearDown() throws Exception {
        stopPeerServers();
    }

    protected void stopPeerServers() {
        for (int i = 0 ; i < PEER_SERVERS ; i++)
            stopPeerServer(i);
    }

    protected void stopPeerServer(int i) {
        peerServers[i].stopAsync();
        peerServers[i].awaitTerminated();
    }

    protected InboundMessageQueuer connect(Peer peer, VersionMessage versionMessage) throws Exception {
        checkArgument(versionMessage.services().has(Services.NODE_NETWORK));
        final AtomicBoolean doneConnecting = new AtomicBoolean(false);
        final Thread thisThread = Thread.currentThread();
        peer.addDisconnectedEventListener((p, peerCount) -> {
            synchronized (doneConnecting) {
                if (!doneConnecting.get())
                    thisThread.interrupt();
            }
        });
        if (clientType == ClientType.NIO_CLIENT_MANAGER || clientType == ClientType.BLOCKING_CLIENT_MANAGER)
            channels.openConnection(new InetSocketAddress(InetAddress.getLoopbackAddress(), 2000), peer);
        else if (clientType == ClientType.NIO_CLIENT)
            new NioClient(new InetSocketAddress(InetAddress.getLoopbackAddress(), 2000), peer, Duration.ofMillis(100));
        else if (clientType == ClientType.BLOCKING_CLIENT)
            new BlockingClient(new InetSocketAddress(InetAddress.getLoopbackAddress(), 2000), peer, Duration.ofMillis(100), SocketFactory.getDefault(), null);
        else
            throw new RuntimeException();
        // Claim we are connected to a different IP that what we really are, so tx confidence broadcastBy sets work
        InboundMessageQueuer writeTarget = newPeerWriteTargetQueue.take();
        writeTarget.peer = peer;
        // Complete handshake with the peer - send/receive version(ack)s, receive bloom filter
        checkState(!peer.getVersionHandshakeFuture().isDone());
        writeTarget.sendMessage(versionMessage);
        writeTarget.sendMessage(new VersionAck());
        try {
            checkState(writeTarget.nextMessageBlocking() instanceof VersionMessage);
            checkState(writeTarget.nextMessageBlocking() instanceof VersionAck);
            peer.getVersionHandshakeFuture().get();
            synchronized (doneConnecting) {
                doneConnecting.set(true);
            }
            Thread.interrupted(); // Clear interrupted bit in case it was set before we got into the CS
        } catch (InterruptedException e) {
            // We were disconnected before we got back version/verack
        }
        return writeTarget;
    }

    protected void closePeer(Peer peer) throws Exception {
        peer.close();
    }

    protected void inbound(InboundMessageQueuer peerChannel, Message message) {
        peerChannel.sendMessage(message);
    }

    private void outboundPingAndWait(final InboundMessageQueuer p, long nonce) throws Exception {
        // Send a ping and wait for it to get to the other side
        CompletableFuture<Void> pingReceivedFuture = new CompletableFuture<>();
        p.mapPingFutures.put(nonce, pingReceivedFuture);
        p.peer.sendMessage(Ping.of(nonce));
        pingReceivedFuture.get();
        p.mapPingFutures.remove(nonce);
    }

    private void inboundPongAndWait(final InboundMessageQueuer p, final long nonce) throws Exception {
        // Receive a ping (that the Peer doesn't see) and wait for it to get through the socket
        final CompletableFuture<Void> pongReceivedFuture = new CompletableFuture<>();
        PreMessageReceivedEventListener listener = (p1, m) -> {
            if (m instanceof Pong && ((Pong) m).nonce() == nonce) {
                pongReceivedFuture.complete(null);
                return null;
            }
            return m;
        };
        p.peer.addPreMessageReceivedEventListener(Threading.SAME_THREAD, listener);
        inbound(p, Pong.of(nonce));
        pongReceivedFuture.get();
        p.peer.removePreMessageReceivedEventListener(listener);
    }

    protected void pingAndWait(final InboundMessageQueuer p) throws Exception {
        final long nonce = (long) (Math.random() * Long.MAX_VALUE);
        // Start with an inbound Pong as pingAndWait often happens immediately after an inbound() call, and then wants
        // to wait on an outbound message, so we do it in the same order or we see race conditions
        inboundPongAndWait(p, nonce);
        outboundPingAndWait(p, nonce);
    }

    protected Message outbound(InboundMessageQueuer p1) throws Exception {
        pingAndWait(p1);
        return p1.nextMessage();
    }

    protected Message waitForOutbound(InboundMessageQueuer ch) throws InterruptedException {
        return ch.nextMessageBlocking();
    }

    protected Peer peerOf(InboundMessageQueuer ch) {
        return ch.peer;
    }
}