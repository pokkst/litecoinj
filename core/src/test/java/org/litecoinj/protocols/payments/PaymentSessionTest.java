/*
 * Copyright 2013 Google Inc.
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

package org.litecoinj.protocols.payments;

import com.google.protobuf.ByteString;
import org.litecoin.protocols.payments.Protos;
import org.litecoinj.base.BitcoinNetwork;
import org.litecoinj.base.ScriptType;
import org.litecoinj.base.Address;
import org.litecoinj.base.Coin;
import org.litecoinj.base.internal.TimeUtils;
import org.litecoinj.core.Context;
import org.litecoinj.core.TransactionOutPoint;
import org.litecoinj.crypto.ECKey;
import org.litecoinj.core.NetworkParameters;
import org.litecoinj.core.Transaction;
import org.litecoinj.core.TransactionInput;
import org.litecoinj.core.TransactionOutput;
import org.litecoinj.crypto.TrustStoreLoader;
import org.litecoinj.params.MainNetParams;
import org.litecoinj.params.TestNet3Params;
import org.litecoinj.utils.ListenableCompletableFuture;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.InputStream;
import java.net.URL;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.litecoinj.base.Coin.COIN;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class PaymentSessionTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();

    private static final String simplePaymentUrl = "http://a.simple.url.com/";
    private static final String paymentRequestMemo = "send coinz noa plz kthx";
    private static final String paymentMemo = "take ze coinz";
    private static final ByteString merchantData = ByteString.copyFromUtf8("merchant data");
    private static final Instant time = TimeUtils.currentTime().truncatedTo(ChronoUnit.SECONDS);
    private ECKey serverKey;
    private Transaction tx;
    private TransactionOutput outputToMe;
    private final Coin amount = COIN;

    @Before
    public void setUp() {
        Context.propagate(new Context());
        serverKey = new ECKey();
        tx = new Transaction();
        outputToMe = new TransactionOutput(tx, amount, serverKey);
        tx.addOutput(outputToMe);
    }

    @Test
    public void testSimplePayment() throws Exception {
        // Create a PaymentRequest and make sure the correct values are parsed by the PaymentSession.
        MockPaymentSession paymentSession = new MockPaymentSession(newSimplePaymentRequest("test"));
        assertEquals(paymentRequestMemo, paymentSession.getMemo());
        assertEquals(amount, paymentSession.getValue());
        assertEquals(simplePaymentUrl, paymentSession.getPaymentUrl());
        assertEquals(time, paymentSession.time());
        assertTrue(paymentSession.getSendRequest().tx.equals(tx));
        assertFalse(paymentSession.isExpired());

        // Send the payment and verify that the correct information is sent.
        // Add a dummy input to tx so it is considered valid.
        tx.addInput(new TransactionInput(tx, outputToMe.getScriptBytes(), TransactionOutPoint.UNCONNECTED));
        ArrayList<Transaction> txns = new ArrayList<>();
        txns.add(tx);
        Address refundAddr = serverKey.toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET);
        paymentSession.sendPayment(txns, refundAddr, paymentMemo);
        assertEquals(1, paymentSession.getPaymentLog().size());
        assertEquals(simplePaymentUrl, paymentSession.getPaymentLog().get(0).getUrl().toString());
        Protos.Payment payment = paymentSession.getPaymentLog().get(0).getPayment();
        assertEquals(paymentMemo, payment.getMemo());
        assertEquals(merchantData, payment.getMerchantData());
        assertEquals(1, payment.getRefundToCount());
        assertEquals(amount.value, payment.getRefundTo(0).getAmount());
        TransactionOutput refundOutput = new TransactionOutput(null, amount, refundAddr);
        ByteString refundScript = ByteString.copyFrom(refundOutput.getScriptBytes());
        assertTrue(refundScript.equals(payment.getRefundTo(0).getScript()));
    }

    @Test
    public void testDefaults() throws Exception {
        Protos.Output.Builder outputBuilder = Protos.Output.newBuilder()
                .setScript(ByteString.copyFrom(outputToMe.getScriptBytes()));
        Protos.PaymentDetails paymentDetails = Protos.PaymentDetails.newBuilder()
                .setTime(time.getEpochSecond())
                .addOutputs(outputBuilder)
                .build();
        Protos.PaymentRequest paymentRequest = Protos.PaymentRequest.newBuilder()
                .setSerializedPaymentDetails(paymentDetails.toByteString())
                .build();
        MockPaymentSession paymentSession = new MockPaymentSession(paymentRequest);
        assertEquals(Coin.ZERO, paymentSession.getValue());
        assertNull(paymentSession.getPaymentUrl());
        assertNull(paymentSession.getMemo());
    }

    @Test
    public void testExpiredPaymentRequest() throws PaymentProtocolException {
        MockPaymentSession paymentSession = new MockPaymentSession(newExpiredPaymentRequest());
        assertTrue(paymentSession.isExpired());
        // Send the payment and verify that an exception is thrown.
        // Add a dummy input to tx so it is considered valid.
        tx.addInput(new TransactionInput(tx, outputToMe.getScriptBytes(), TransactionOutPoint.UNCONNECTED));
        ArrayList<Transaction> txns = new ArrayList<>();
        txns.add(tx);

        CompletableFuture<PaymentProtocol.Ack> ack = paymentSession.sendPayment(txns, null, null);
        try {
            ack.get();
        } catch (ExecutionException e) {
            if (e.getCause() instanceof PaymentProtocolException.Expired) {
                PaymentProtocolException.Expired cause = (PaymentProtocolException.Expired) e.getCause();
                assertEquals(0, paymentSession.getPaymentLog().size());
                assertEquals(cause.getMessage(), "PaymentRequest is expired");
                return;
            }
        } catch (InterruptedException e) {
            // Ignore
        }
        fail("Expected exception due to expired PaymentRequest");
    }

    @Test
    @Ignore("certificate expired")
    public void testPkiVerification() throws Exception {
        InputStream in = getClass().getResourceAsStream("pki_test.bitcoinpaymentrequest");
        Protos.PaymentRequest paymentRequest = Protos.PaymentRequest.newBuilder().mergeFrom(in).build();
        PaymentProtocol.PkiVerificationData pkiData = PaymentProtocol.verifyPaymentRequestPki(paymentRequest,
                new TrustStoreLoader.DefaultTrustStoreLoader().getKeyStore());
        assertEquals("www.bitcoincore.org", pkiData.displayName);
        assertEquals("The USERTRUST Network, Salt Lake City, US", pkiData.rootAuthorityName);
    }

    private Protos.PaymentRequest newSimplePaymentRequest(String netID) {
        Protos.Output.Builder outputBuilder = Protos.Output.newBuilder()
                .setAmount(amount.value)
                .setScript(ByteString.copyFrom(outputToMe.getScriptBytes()));
        Protos.PaymentDetails paymentDetails = Protos.PaymentDetails.newBuilder()
                .setNetwork(netID)
                .setTime(time.getEpochSecond())
                .setPaymentUrl(simplePaymentUrl)
                .addOutputs(outputBuilder)
                .setMemo(paymentRequestMemo)
                .setMerchantData(merchantData)
                .build();
        return Protos.PaymentRequest.newBuilder()
                .setPaymentDetailsVersion(1)
                .setPkiType("none")
                .setSerializedPaymentDetails(paymentDetails.toByteString())
                .build();
    }

    private Protos.PaymentRequest newExpiredPaymentRequest() {
        Protos.Output.Builder outputBuilder = Protos.Output.newBuilder()
                .setAmount(amount.value)
                .setScript(ByteString.copyFrom(outputToMe.getScriptBytes()));
        Protos.PaymentDetails paymentDetails = Protos.PaymentDetails.newBuilder()
                .setNetwork("test")
                .setTime(time.minusSeconds(10).getEpochSecond())
                .setExpires(time.minusSeconds(1).getEpochSecond())
                .setPaymentUrl(simplePaymentUrl)
                .addOutputs(outputBuilder)
                .setMemo(paymentRequestMemo)
                .setMerchantData(merchantData)
                .build();
        return Protos.PaymentRequest.newBuilder()
                .setPaymentDetailsVersion(1)
                .setPkiType("none")
                .setSerializedPaymentDetails(paymentDetails.toByteString())
                .build();
    }

    private static class MockPaymentSession extends PaymentSession {
        private final ArrayList<PaymentLogItem> paymentLog = new ArrayList<>();

        public MockPaymentSession(Protos.PaymentRequest request) throws PaymentProtocolException {
            super(request);
        }

        public ArrayList<PaymentLogItem> getPaymentLog() {
            return paymentLog;
        }

        @Override
        protected ListenableCompletableFuture<PaymentProtocol.Ack> sendPayment(final URL url, final Protos.Payment payment) {
            paymentLog.add(new PaymentLogItem(url, payment));
            // Return a completed future that has a `null` value. This will satisfy the current tests.
            return ListenableCompletableFuture.completedFuture(null);
        }

        public static class PaymentLogItem {
            private final URL url;
            private final Protos.Payment payment;

            PaymentLogItem(final URL url, final Protos.Payment payment) {
                this.url = url;
                this.payment = payment;
            }

            public URL getUrl() {
                return url;
            }

            public Protos.Payment getPayment() {
                return payment;
            }
        }
    }
}
