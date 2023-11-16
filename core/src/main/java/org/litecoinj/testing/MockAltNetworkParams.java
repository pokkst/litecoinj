/*
 * Copyright by the original author or authors.
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

import org.litecoinj.base.Coin;
import org.litecoinj.base.utils.MonetaryFormat;
import org.litecoinj.core.BitcoinSerializer;
import org.litecoinj.core.Block;
import org.litecoinj.core.NetworkParameters;
import org.litecoinj.core.StoredBlock;
import org.litecoinj.core.VerificationException;
import org.litecoinj.store.BlockStore;
import org.litecoinj.store.BlockStoreException;

/**
 * Mock Alt-net subclass of {@link NetworkParameters} for unit tests.
 */
public class MockAltNetworkParams extends NetworkParameters {
    public static final String MOCKNET_GOOD_ADDRESS = "LLxSnHLN2CYyzB5eWTR9K9rS9uWtbTQFb6";

    public MockAltNetworkParams() {
        super(new MockAltNetwork());
    }

    @Override
    public String getPaymentProtocolId() {
        return null;
    }

    @Override
    public void checkDifficultyTransitions(StoredBlock storedPrev, Block next, BlockStore blockStore) throws VerificationException, BlockStoreException {

    }

    @Override
    public Block getGenesisBlock() {
        return null;
    }

    @Override
    public Coin getMaxMoney() {
        return (Coin) this.network.maxMoney();
    }

    @Override
    public MonetaryFormat getMonetaryFormat() {
        return null;
    }

    @Override
    public String getUriScheme() {
        return this.network.uriScheme();
    }

    @Override
    public boolean hasMaxMoney() {
        return this.network.hasMaxMoney();
    }

    @Override
    public BitcoinSerializer getSerializer() {
        return null;
    }
}
