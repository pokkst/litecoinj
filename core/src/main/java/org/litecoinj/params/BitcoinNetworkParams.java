/*
 * Copyright 2013 Google Inc.
 * Copyright 2015 Andreas Schildbach
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

package org.litecoinj.params;

import org.litecoinj.base.BitcoinNetwork;
import org.litecoinj.base.internal.Stopwatch;
import org.litecoinj.base.internal.ByteUtils;
import org.litecoinj.core.BitcoinSerializer;
import org.litecoinj.core.Block;
import org.litecoinj.base.Coin;
import org.litecoinj.core.NetworkParameters;
import org.litecoinj.base.Sha256Hash;
import org.litecoinj.core.StoredBlock;
import org.litecoinj.core.VerificationException;
import org.litecoinj.protocols.payments.PaymentProtocol;
import org.litecoinj.store.BlockStore;
import org.litecoinj.store.BlockStoreException;
import org.litecoinj.base.utils.MonetaryFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.math.BigInteger;

import static org.litecoinj.base.internal.Preconditions.checkState;

/**
 * Parameters for Bitcoin-like networks.
 */
public abstract class BitcoinNetworkParams extends NetworkParameters {

    /**
     * Scheme part for Bitcoin URIs.
     * @deprecated Use {@link BitcoinNetwork#BITCOIN_SCHEME}
     */
    @Deprecated
    public static final String BITCOIN_SCHEME = BitcoinNetwork.BITCOIN_SCHEME;

    /**
     * Block reward halving interval (number of blocks)
     */
    public static final int REWARD_HALVING_INTERVAL = 840_000;

    private static final Logger log = LoggerFactory.getLogger(BitcoinNetworkParams.class);

    /** lazy-initialized by the first call to {@link NetworkParameters#getGenesisBlock()} */
    protected Block genesisBlock;

    /**
     * No-args constructor
     */
    public BitcoinNetworkParams(BitcoinNetwork network) {
        super(network);
        interval = INTERVAL;
        subsidyDecreaseBlockCount = REWARD_HALVING_INTERVAL;
    }

    /**
     * Return network parameters for a network id
     * @param id the network id
     * @return the network parameters for the given string ID or NULL if not recognized
     */
    @Nullable
    public static BitcoinNetworkParams fromID(String id) {
        if (id.equals(BitcoinNetwork.ID_MAINNET)) {
            return MainNetParams.get();
        } else if (id.equals(BitcoinNetwork.ID_TESTNET)) {
            return TestNet3Params.get();
        } else if (id.equals(BitcoinNetwork.ID_SIGNET)) {
            return SigNetParams.get();
        } else if (id.equals(BitcoinNetwork.ID_REGTEST)) {
            return RegTestParams.get();
        } else {
            return null;
        }
    }

    /**
     * Return network parameters for a {@link BitcoinNetwork} enum
     * @param network the network
     * @return the network parameters for the given string ID
     * @throws IllegalArgumentException if unknown network
     */
    public static BitcoinNetworkParams of(BitcoinNetwork network) {
        switch (network) {
            case MAINNET:
                return MainNetParams.get();
            case TESTNET:
                return TestNet3Params.get();
            case SIGNET:
                return SigNetParams.get();
            case REGTEST:
                return RegTestParams.get();
            default:
                throw new IllegalArgumentException("Unknown network");
        }
    }

    /**
     * @return the payment protocol network id string
     * @deprecated Use {@link PaymentProtocol#protocolIdFromParams(NetworkParameters)}
     */
    @Deprecated
    public String getPaymentProtocolId() {
        return PaymentProtocol.protocolIdFromParams(this);
    }

    /**
     * Checks if we are at a reward halving point.
     * @param previousHeight The height of the previous stored block
     * @return If this is a reward halving point
     */
    public final boolean isRewardHalvingPoint(final int previousHeight) {
        return ((previousHeight + 1) % REWARD_HALVING_INTERVAL) == 0;
    }

    /**
     * <p>A utility method that calculates how much new Bitcoin would be created by the block at the given height.
     * The inflation of Bitcoin is predictable and drops roughly every 4 years (210,000 blocks). At the dawn of
     * the system it was 50 coins per block, in late 2012 it went to 25 coins per block, and so on. The size of
     * a coinbase transaction is inflation plus fees.</p>
     *
     * <p>The half-life is controlled by {@link NetworkParameters#getSubsidyDecreaseBlockCount()}.</p>
     *
     * @param height the height of the block to calculate inflation for
     * @return block reward (inflation) for specified block
     */
    public Coin getBlockInflation(int height) {
        return Coin.FIFTY_COINS.shiftRight(height / getSubsidyDecreaseBlockCount());
    }

    /**
     * Checks if we are at a difficulty transition point.
     * @param previousHeight The height of the previous stored block
     * @return If this is a difficulty transition point
     */
    public final boolean isDifficultyTransitionPoint(final int previousHeight) {
        return ((previousHeight + 1) % this.getInterval()) == 0;
    }

    @Override
    public void checkDifficultyTransitions(final StoredBlock storedPrev, final Block nextBlock,
                                           final BlockStore blockStore) throws VerificationException, BlockStoreException {
        final Block prev = storedPrev.getHeader();

        // Is this supposed to be a difficulty transition point?
        if (!isDifficultyTransitionPoint(storedPrev.getHeight())) {

            // No ... so check the difficulty didn't actually change.
            if (nextBlock.getDifficultyTarget() != prev.getDifficultyTarget())
                throw new VerificationException("Unexpected change in difficulty at height " + storedPrev.getHeight() +
                        ": " + Long.toHexString(nextBlock.getDifficultyTarget()) + " vs " +
                        Long.toHexString(prev.getDifficultyTarget()));
            return;
        }

        // We need to find a block far back in the chain. It's OK that this is expensive because it only occurs every
        // two weeks after the initial block chain download.
        final Stopwatch watch = Stopwatch.start();
        Sha256Hash hash = prev.getHash();
        StoredBlock cursor = blockStore.get(hash);;
        long blocksToGoBack = this.getInterval()-1;
        if(storedPrev.getHeight()+1 != this.getInterval()) {
            blocksToGoBack = this.getInterval();
        }
        for (int i = 0; i < blocksToGoBack; i++) {
            hash = cursor.getHeader().getPrevBlockHash();
            cursor = blockStore.get(hash);
            if (cursor == null) {
                // This should never happen. If it does, it means we are following an incorrect or busted chain.
                throw new VerificationException(
                        "Difficulty transition point but we did not find a way back to the last transition point. Not found: " + hash);
            }
        }
        checkState(cursor != null, () -> "No block found for difficulty transition.");
        boolean isDifficultyTransitionPoint = false;
        if(blocksToGoBack == this.getInterval()-1) {
            isDifficultyTransitionPoint = isDifficultyTransitionPoint(cursor.getHeight()-1);
        } else if(blocksToGoBack == this.getInterval()) {
            isDifficultyTransitionPoint = isDifficultyTransitionPoint(cursor.getHeight());
        }
        checkState(isDifficultyTransitionPoint,
                () -> "Didn't arrive at a transition point.");
        watch.stop();
        if (watch.elapsed().toMillis() > 50)
            log.info("Difficulty transition traversal took {}", watch);

        Block blockIntervalAgo = cursor.getHeader();
        int timespan = (int) (prev.getTimeSeconds() - blockIntervalAgo.getTimeSeconds());
        // Limit the adjustment step.
        final int targetTimespan = this.getTargetTimespan();
        if (timespan < targetTimespan / 4)
            timespan = targetTimespan / 4;
        if (timespan > targetTimespan * 4)
            timespan = targetTimespan * 4;

        BigInteger newTarget = ByteUtils.decodeCompactBits(prev.getDifficultyTarget());
        boolean fShift = newTarget.compareTo(maxTarget.subtract(BigInteger.ONE)) > 0;
        if(fShift)
            newTarget = newTarget.shiftRight(1);
        newTarget = newTarget.multiply(BigInteger.valueOf(timespan));
        newTarget = newTarget.divide(BigInteger.valueOf(targetTimespan));
        if(fShift)
            newTarget = newTarget.shiftLeft(1);

        if (newTarget.compareTo(this.getMaxTarget()) > 0) {
            log.info("Difficulty hit proof of work limit: {}", newTarget.toString(16));
            newTarget = this.getMaxTarget();
        }

        int accuracyBytes = (int) (nextBlock.getDifficultyTarget() >>> 24) - 3;
        long receivedTargetCompact = nextBlock.getDifficultyTarget();

        // The calculated difficulty is to a higher precision than received, so reduce here.
        BigInteger mask = BigInteger.valueOf(0xFFFFFFL).shiftLeft(accuracyBytes * 8);
        newTarget = newTarget.and(mask);
        long newTargetCompact = ByteUtils.encodeCompactBits(newTarget);

        if (newTargetCompact != receivedTargetCompact)
            throw new VerificationException("Network provided difficulty bits do not match what was calculated: " +
                    Long.toHexString(newTargetCompact) + " vs " + Long.toHexString(receivedTargetCompact));
    }

    @Override
    @Deprecated
    public Coin getMaxMoney() {
        return BitcoinNetwork.MAX_MONEY;
    }

    /**
     * @deprecated Get one another way or construct your own {@link MonetaryFormat} as needed.
     */
    @Override
    @Deprecated
    public MonetaryFormat getMonetaryFormat() {
        return new MonetaryFormat();
    }

    @Override
    public BitcoinSerializer getSerializer() {
        return new BitcoinSerializer(this);
    }

    @Override
    @Deprecated
    public String getUriScheme() {
        return BitcoinNetwork.BITCOIN_SCHEME;
    }

    @Override
    @Deprecated
    public boolean hasMaxMoney() {
        return network().hasMaxMoney();
    }
}
