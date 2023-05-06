package org.bitcoinj.wallet;

import com.google.protobuf.ByteString;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.internal.Preconditions;
import org.bitcoinj.core.BloomFilter;
import org.bitcoinj.crypto.*;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;

import javax.annotation.Nullable;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static com.google.common.base.Preconditions.checkState;
import static org.bitcoinj.base.internal.Preconditions.checkArgument;

public class NestedSegwitKeyChain extends DeterministicKeyChain {
    private LinkedHashMap<ByteString, RedeemData> p2shP2wpkhRedeemData = new LinkedHashMap<>();

    public static class Builder<T extends Builder<T>> {
        protected SecureRandom random;
        protected int bits = DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS;
        protected String passphrase;
        @Nullable protected Instant creationTime = null;
        protected byte[] entropy;
        protected DeterministicSeed seed;
        protected ScriptType outputScriptType = ScriptType.P2PKH;
        protected DeterministicKey watchingKey = null;
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
         * if the starting entropy is the same. You should provide the creation time for the
         * chain: this lets us know from what part of the chain we can expect to see derived keys appear.
         * @param entropy entropy to create the chain with
         * @param creationTime creation time for the chain
         */
        public T entropy(byte[] entropy, Instant creationTime) {
            this.entropy = entropy;
            this.creationTime = Objects.requireNonNull(creationTime);
            return self();
        }

        /** @deprecated use {@link #entropy(byte[], Instant)} */
        @Deprecated
        public T entropy(byte[] entropy, long creationTimeSecs) {
            checkArgument(creationTimeSecs > 0);
            return entropy(entropy, Instant.ofEpochSecond(creationTimeSecs));
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
            Preconditions.checkState(accountPath == null, () ->
                    "either watch or accountPath");
            this.watchingKey = accountKey;
            return self();
        }

        /**
         * Creates a key chain that can spend from the given account key.
         */
        public T spend(DeterministicKey accountKey) {
            Preconditions.checkState(accountPath == null, () ->
                    "either spend or accountPath");
            this.spendingKey = accountKey;
            return self();
        }

        public T outputScriptType(ScriptType outputScriptType) {
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
         * Use an account path other than the default {@link DeterministicKeyChain#ACCOUNT_ZERO_PATH}.
         */
        public T accountPath(List<ChildNumber> accountPath) {
            Preconditions.checkState(watchingKey == null, () ->
                    "either watch or accountPath");
            this.accountPath = HDPath.M(Objects.requireNonNull(accountPath));
            return self();
        }

        public NestedSegwitKeyChain build() {
            Preconditions.checkState(passphrase == null || seed == null, () ->
                    "passphrase must not be specified with seed");

            if (accountPath == null)
                accountPath = BIP44_ACCOUNT_ZERO_PATH;

            if (random != null)
                // Default passphrase to "" if not specified
                return new NestedSegwitKeyChain(DeterministicSeed.ofRandom(random, bits, getPassphrase()), null,
                        outputScriptType, accountPath);
            else if (entropy != null)
                return new NestedSegwitKeyChain(DeterministicSeed.ofEntropy(entropy, getPassphrase(), creationTime),
                        null, outputScriptType, accountPath);
            else if (seed != null)
                return new NestedSegwitKeyChain(seed, null, outputScriptType, accountPath);
            else if (watchingKey != null)
                return new NestedSegwitKeyChain(watchingKey, false, true, outputScriptType);
            else if (spendingKey != null)
                return new NestedSegwitKeyChain(spendingKey, false, false, outputScriptType);
            else
                throw new IllegalStateException();
        }

        protected String getPassphrase() {
            return passphrase != null ? passphrase : DEFAULT_PASSPHRASE_FOR_MNEMONIC;
        }
    }

    public static Builder<?> nestedSegwitBuilder() {
        return new Builder<>();
    }

    public NestedSegwitKeyChain(DeterministicKey key, boolean isFollowing, boolean isWatching, ScriptType outputScriptType) {
        super(key, isFollowing, isWatching, outputScriptType);
    }

    protected NestedSegwitKeyChain(DeterministicSeed seed, @Nullable KeyCrypter crypter, ScriptType outputScriptType, List<ChildNumber> accountPath) {
        super(seed, crypter, outputScriptType, accountPath);
    }

    protected NestedSegwitKeyChain(KeyCrypter crypter, AesKey aesKey, DeterministicKeyChain chain) {
        super(crypter, aesKey, chain);
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
    public BloomFilter getFilter(int size, double falsePositiveRate, int tweak) {
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
