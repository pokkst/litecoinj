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

package org.bitcoinj.wallet;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.protobuf.ByteString;

import org.bitcoinj.core.BloomFilter;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.*;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.utils.Threading;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * <p>A multi-signature keychain using synchronized HD keys (a.k.a HDM)</p>
 * <p>This keychain keeps track of following keychains that follow the account key of this keychain.
 * You can get P2SH addresses to receive coins to from this chain. The threshold - sigsRequiredToSpend
 * specifies how many signatures required to spend transactions for this married keychain. This value should not exceed
 * total number of keys involved (one followed key plus number of following keys), otherwise IllegalArgumentException
 * will be thrown.</p>
 * <p>IMPORTANT: As of Bitcoin Core 0.9 all bare (non-P2SH) multisig transactions which require more than 3 public keys are non-standard
 * and such spends won't be processed by peers with default settings, essentially making such transactions almost
 * nonspendable</p>
 * <p>This method will throw an IllegalStateException, if the keychain is already married or already has leaf keys
 * issued.</p>
 */
public class NestedSegwitKeyChain extends DeterministicKeyChain {
    protected final ReentrantLock lock = Threading.lock(DeterministicKeyChain.class);

    // The map holds P2SH redeem script and corresponding ECKeys issued by this KeyChainGroup (including lookahead)
    // mapped to redeem script hashes.
    private LinkedHashMap<ByteString, RedeemData> p2shP2wpkhRedeemData = new LinkedHashMap<>();

    public static class Builder<T extends Builder<T>> extends DeterministicKeyChain.Builder<T> {
        protected SecureRandom random;
        protected int bits = DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS;
        protected String passphrase;
        protected long creationTimeSecs = 0;
        protected byte[] entropy;
        protected DeterministicSeed seed;
        protected Script.ScriptType outputScriptType = Script.ScriptType.P2PKH;
        protected DeterministicKey watchingKey = null;
        protected boolean isFollowing = false;
        protected DeterministicKey spendingKey = null;
        protected HDPath accountPath = null;

        protected Builder() {
        }

        @SuppressWarnings("unchecked")
        protected T self() {
            return (T)this;
        }

        /**
         * Creates a deterministic key chain starting from the given entropy. All keys yielded by this chain will be the same
         * if the starting entropy is the same. You should provide the creation time in seconds since the UNIX epoch for the
         * seed: this lets us know from what part of the chain we can expect to see derived keys appear.
         */
        public T entropy(byte[] entropy, long creationTimeSecs) {
            this.entropy = entropy;
            this.creationTimeSecs = creationTimeSecs;
            return self();
        }

        /**
         * Creates a deterministic key chain starting from the given seed. All keys yielded by this chain will be the same
         * if the starting seed is the same.
         */
        public T seed(DeterministicSeed seed) {
            this.seed = seed;
            return self();
        }

        /**
         * Generates a new key chain with entropy selected randomly from the given {@link SecureRandom}
         * object and of the requested size in bits.  The derived seed is further protected with a user selected passphrase
         * (see BIP 39).
         * @param random the random number generator - use new SecureRandom().
         * @param bits The number of bits of entropy to use when generating entropy.  Either 128 (default), 192 or 256.
         */
        public T random(SecureRandom random, int bits) {
            this.random = random;
            this.bits = bits;
            return self();
        }

        /**
         * Generates a new key chain with 128 bits of entropy selected randomly from the given {@link SecureRandom}
         * object.  The derived seed is further protected with a user selected passphrase
         * (see BIP 39).
         * @param random the random number generator - use new SecureRandom().
         */
        public T random(SecureRandom random) {
            this.random = random;
            return self();
        }

        /**
         * Creates a key chain that watches the given account key.
         */
        public T watch(DeterministicKey accountKey) {
            checkState(accountPath == null, "either watch or accountPath");
            this.watchingKey = accountKey;
            this.isFollowing = false;
            return self();
        }

        /**
         * Creates a deterministic key chain with the given watch key and that follows some other keychain. In a married
         * wallet following keychain represents "spouse". Watch key has to be an account key.
         */
        public T watchAndFollow(DeterministicKey accountKey) {
            checkState(accountPath == null, "either watchAndFollow or accountPath");
            this.watchingKey = accountKey;
            this.isFollowing = true;
            return self();
        }

        /**
         * Creates a key chain that can spend from the given account key.
         */
        public T spend(DeterministicKey accountKey) {
            checkState(accountPath == null, "either spend or accountPath");
            this.spendingKey = accountKey;
            this.isFollowing = false;
            return self();
        }

        public T outputScriptType(Script.ScriptType outputScriptType) {
            this.outputScriptType = outputScriptType;
            return self();
        }

        /** The passphrase to use with the generated mnemonic, or null if you would like to use the default empty string. Currently must be the empty string. */
        public T passphrase(String passphrase) {
            // FIXME support non-empty passphrase
            this.passphrase = passphrase;
            return self();
        }

        /**
         * Use an account path other than the default {@link DeterministicKeyChain#BIP44_ACCOUNT_ZERO_PATH}.
         */
        public T accountPath(List<ChildNumber> accountPath) {
            checkState(watchingKey == null, "either watch or accountPath");
            this.accountPath = HDPath.M(checkNotNull(accountPath));
            return self();
        }

        public NestedSegwitKeyChain build() {
            checkState(passphrase == null || seed == null, "Passphrase must not be specified with seed");

            if (accountPath == null)
                accountPath = BIP44_ACCOUNT_ZERO_PATH;

            if (random != null)
                // Default passphrase to "" if not specified
                return new NestedSegwitKeyChain(new DeterministicSeed(random, bits, getPassphrase()), null,
                        outputScriptType, accountPath);
            else if (entropy != null)
                return new NestedSegwitKeyChain(new DeterministicSeed(entropy, getPassphrase(), creationTimeSecs),
                        null, outputScriptType, accountPath);
            else if (seed != null)
                return new NestedSegwitKeyChain(seed, null, outputScriptType, accountPath);
            else if (watchingKey != null)
                return new NestedSegwitKeyChain(watchingKey, isFollowing, true, outputScriptType);
            else if (spendingKey != null)
                return new NestedSegwitKeyChain(spendingKey, false, false, outputScriptType);
            else
                throw new IllegalStateException();
        }

        protected String getPassphrase() {
            return passphrase != null ? passphrase : DEFAULT_PASSPHRASE_FOR_MNEMONIC;
        }
    }

    public static Builder<?> builder() {
        return new Builder();
    }

    /**
     * This constructor is not stable across releases! If you need a stable API, use {@link #builder()} to use a
     * {@link Builder}.
     */
    protected NestedSegwitKeyChain(DeterministicKey accountKey, Script.ScriptType outputScriptType) {
        super(accountKey, false, true, outputScriptType);
    }

    /**
     * This constructor is not stable across releases! If you need a stable API, use {@link #builder()} to use a
     * {@link Builder}.
     */
    protected NestedSegwitKeyChain(DeterministicSeed seed, KeyCrypter crypter, Script.ScriptType outputScriptType, List<ChildNumber> accountPath) {
        super(seed, crypter, outputScriptType, accountPath);
    }

    public NestedSegwitKeyChain(DeterministicKey key, boolean isFollowing, boolean isWatching,
                                 Script.ScriptType outputScriptType) {
        super(key, isFollowing, isWatching, outputScriptType);
    }

    @Override
    public boolean isMarried() {
        return false;
    }

    @Override
    public boolean isNestedSegwit() {
        return true;
    }

    /** Create a new married key and return the matching output script */
    @Override
    public Script freshOutputScript(KeyPurpose purpose) {
        DeterministicKey myKey = getKey(purpose);
        return ScriptBuilder.createP2SHP2WPKHOutputScript(myKey);
    }

    /** Get the redeem data for a key in this married chain */
    @Override
    public RedeemData getRedeemData(DeterministicKey myKey) {
        Script redeemScript = ScriptBuilder.createP2SHP2WPKHRedeemScript(myKey);
        return RedeemData.of(myKey, redeemScript);
    }

    @Override
    public List<Protos.Key> serializeToProtobuf() {
        List<Protos.Key> result = new ArrayList<>();
        lock.lock();
        try {
            result.addAll(serializeMyselfToProtobuf());
        } finally {
            lock.unlock();
        }
        return result;
    }

    @Override
    protected void formatAddresses(boolean includeLookahead, boolean includePrivateKeys, @Nullable KeyParameter aesKey,
                                   NetworkParameters params, StringBuilder builder) {
        builder.append('\n');
        for (RedeemData redeemData : p2shP2wpkhRedeemData.values())
            formatScript(ScriptBuilder.createP2SHOutputScript(redeemData.redeemScript), builder, params);
    }

    private void formatScript(Script script, StringBuilder builder, NetworkParameters params) {
        builder.append("  addr:");
        builder.append(script.getToAddress(params));
        builder.append("  hash160:");
        builder.append(Utils.HEX.encode(script.getPubKeyHash()));
        if (script.getCreationTimeSeconds() > 0)
            builder.append("  creationTimeSeconds:").append(script.getCreationTimeSeconds());
        builder.append('\n');
    }

    @Override
    public void maybeLookAheadScripts() {
        super.maybeLookAheadScripts();
        int numLeafKeys = getLeafKeys().size();

        checkState(p2shP2wpkhRedeemData.size() <= numLeafKeys, "Number of scripts is greater than number of leaf keys");
        if (p2shP2wpkhRedeemData.size() == numLeafKeys)
            return;

        maybeLookAhead();
        for (DeterministicKey followedKey : getLeafKeys()) {
            RedeemData redeemData = getRedeemData(followedKey);
            Script scriptPubKey = ScriptBuilder.createP2SHOutputScript(redeemData.redeemScript);
            p2shP2wpkhRedeemData.put(ByteString.copyFrom(scriptPubKey.getPubKeyHash()), redeemData);
        }
    }

    @Nullable
    @Override
    public RedeemData findRedeemDataByScriptHash(ByteString bytes) {
        return p2shP2wpkhRedeemData.get(bytes);
    }

    @Override
    public BloomFilter getFilter(int size, double falsePositiveRate, long tweak) {
        lock.lock();
        BloomFilter filter;
        try {
            filter = new BloomFilter(size, falsePositiveRate, tweak);
            for (Map.Entry<ByteString, RedeemData> entry : p2shP2wpkhRedeemData.entrySet()) {
                filter.insert(entry.getKey().toByteArray());
                filter.insert(entry.getValue().redeemScript.getProgram());
            }
        } finally {
            lock.unlock();
        }
        return filter;
    }

    @Override
    public int numBloomFilterEntries() {
        maybeLookAhead();
        return getLeafKeys().size() * 2;
    }
}
