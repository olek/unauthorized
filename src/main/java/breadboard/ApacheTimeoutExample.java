package breadboard;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import io.undertow.Undertow;
import io.undertow.UndertowOptions;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.HttpContext;

/**
 * Reproducing issue for apache client not using CredentialsProvider after prior
 * timeout.
 *
 * Test scenario: submitting 3 requests to same site with 3 different set of
 * credentials, timing out response on first authorized request.
 *
 * Expected result: 3 pairs of http requests observed on http server (with pair
 * defined as sequence of unauthorized and authorized requests), with this
 * output
 *
 * ======== Starting the test
 * ======== Sending client request 1
 * ======== Received server request 1 at /account/2544
 * ======== Missing Authorization header, returning 401
 * ======== Received server request 2 at /account/2544
 * ======== Authorization password pass-2544 matches account
 * ======== Http server trigerring socket timeout, sleeping
 * ======== Client request 1 timed out
 * ======== Sending client request 2
 * ======== Received server request 3 at /account/1656
 * ======== Missing Authorization header, returning 401
 * ======== Received server request 4 at /account/1656
 * ======== Authorization password pass-1656 matches account
 * ======== Http server returning 200 for server request 4
 * ======== Response to client request 2 - 200
 * ======== Sending client request 3
 * ======== Received server request 5 at /account/5598
 * ======== Authorization password pass-1656 does not match account 5598
 * ======== Received server request 6 at /account/5598
 * ======== Authorization password pass-5598 matches account
 * ======== Http server returning 200 for server request 6
 * ======== Response to client request 3 - 200
 *
 * Note: ideally, apache http client should realize that since different
 * CredentialsProvider is sent to it, previously used/cached credentials should
 * not be reused, but sending wrong credentials followed by right credentials
 * (while far from being ideal) still allows arriving at correct result;
 * workaround is to reset AuthState manually, that prevents sending wrong
 * credentials, fixing enless 401's as well.
 *
 * Actual result: 4 http requests observed on http server (one pair and two
 * singular requests), with this output:
 *
 * ======= Received server request 1 at /account/7039
 * ======== Missing Authorization header, returning 401
 * ======== Received server request 2 at /account/7039
 * ======== Authorization password pass-7039 matches account
 * ======== Http server trigerring socket timeout, sleeping
 * ======== Client request 1 timed out
 * ======== Sending client request 2
 * ======== Received server request 3 at /account/4958
 * ======== Authorization password pass-7039 does not match account 4958
 * ======== Response to client request 2 - 401
 * ======== Sending client request 3
 * ======== Received server request 4 at /account/6491
 * ======== Missing Authorization header, returning 401
 * ======== Response to client request 3 - 401
 *
 * Issue: after encountering scenario where unauthorized request does not time
 * out but following authorized request times out, http client goes into 'bad'
 * state where unauthorized (or mis-authorized) request is NOT followed with
 * another request that uses CredentialsProvider to generate authorization
 * header. That 'bad' state persists forever, never repairing itself, causing
 * ALL following http requests to fail.
 */
public class ApacheTimeoutExample {
    private static final boolean TRIGGER_TIMEOUT = true;

    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 8089;
    private static final String TEST_URL_PREFIX = String.format("http://%s:%d/account/", SERVER_HOST, SERVER_PORT);
    private static final String USER_PREFIX = "user-";
    private static final String PASSWORD_PREFIX = "pass-";

    private static final int CONNECT_TIMEOUT = 100;
    private static final int READ_TIMEOUT = 1000;
    private static final Random randomGenerator = new Random();

    public static void main( String[] args ) {
        Undertow httpServer = startHttpServer();

        try {
            runTest();
        } finally {
            httpServer.stop();
        }
    }

    private static void runTest() {
        println("Starting the test");

        try {
            final CloseableHttpClient client = createHttpClient();

            final HttpClientContext context = HttpClientContext.create();

            for (int requestIndex = 1; requestIndex < 4 ; requestIndex++) {
                // Lets pretend that next request is on behalf of a different user
                // and requires different set of credentials.
                final String randomId = generateRandomId();

                context.setCredentialsProvider(createCredentialsProvider(randomId));

                try {
                    println("Sending client request " + requestIndex);

                    CloseableHttpResponse response = client.execute(createPostRequest(randomId), context);

                    println("Response to client request " + requestIndex + " - " +
                            response.getStatusLine().getStatusCode());
                    response.close();
                } catch (SocketTimeoutException e) {
                    println("Client request " + requestIndex + " timed out");
                } finally {
                    // Clearing auth-cache makes apache forget that server
                    // demands basic auth, not exactly useful in this scenario.
                    //
                    if (false && context.getAuthCache() != null) {
                        println("Cleared auth cache after client request " + requestIndex);
                        context.getAuthCache().clear();
                    }
                    //
                    // Clearing auth-sate not only makes apache forget the
                    // credentials that worked for previous request (good,
                    // forces it fetch potentially different credentials from
                    // CredentialsProvider), but also fixes issues with endless
                    // fatal 401's after timeout.
                    //
                    if (false && context.getTargetAuthState() != null) {
                        println("Reset auth state after client request " + requestIndex);
                        context.getTargetAuthState().reset();
                    }
                }
            }
        } catch (IOException e) {
            println("Caught " + e);
        }
    }

    private static Undertow startHttpServer() {
        println("Starting the http server");

        Undertow server = Undertow.builder()
            .addHttpListener(SERVER_PORT, SERVER_HOST)
            .setHandler(new MyHttpHandler())
            .build();
        server.start();

        return server;
    }

    private static CloseableHttpClient createHttpClient() {
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(CONNECT_TIMEOUT)
                .setSocketTimeout(READ_TIMEOUT)
                .build();

        CloseableHttpClient client = HttpClientBuilder.create()
            .setDefaultRequestConfig(requestConfig)
            .build();

        return client;
    }

    private static String generateRandomId() {
        return String.format("%04d", randomGenerator.nextInt(10000));
    }

    private static CredentialsProvider createCredentialsProvider(String randomId) {
        String user = USER_PREFIX + randomId;
        String password = PASSWORD_PREFIX + randomId;

        UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(user, password);

        CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY, credentials);

        return credentialsProvider;
    }

    private static HttpPost createPostRequest(String randomId) throws IOException {
        HttpPost httpPost = new HttpPost(TEST_URL_PREFIX + randomId);

        return httpPost;
    }

    private static void println(String msg) {
        System.out.println("======== " + msg);
    }

    // Implements endpoint used in this test, that requires basic authentication
    // and checks provided credentials agains account id found in url
    private static class MyHttpHandler implements HttpHandler {
        private static AtomicInteger requestIndexCounter = new AtomicInteger(0);

        @Override
        public void handleRequest(final HttpServerExchange exchange) throws Exception {
            final int requestIndex = requestIndexCounter.addAndGet(1);

            println("Received server request " + requestIndex + " at " + exchange.getRelativePath());

            final String accountId = StringUtils.substringAfterLast(exchange.getRelativePath(), "/");

            if (StringUtils.isBlank(accountId)) {
                println("Missing account id");
                exchange.setResponseCode(400);

                return;
            }

            final String authorizationHeader = exchange.getRequestHeaders().getFirst("Authorization");

            if (authorizationHeader == null) {
                println("Missing Authorization header, returning 401");
                exchange.setResponseCode(401);
                exchange.getResponseHeaders().put(Headers.WWW_AUTHENTICATE, "Basic realm=test");

                return;
            }

            // Assuming header starts with "Basic "
            final String authorizationPair = new String(Base64.decodeBase64(authorizationHeader.substring(6)));
            final String password = StringUtils.substringAfterLast(authorizationPair, ":");
            if (StringUtils.isBlank(password)) {
                println("Invalid 'Authorization' header value " + authorizationHeader);
                exchange.setResponseCode(400);

                return;
            }

            final String verificationPassword = PASSWORD_PREFIX + accountId;

            if (password.equals(verificationPassword)) {
                println("Authorization password " + password + " matches account");
            } else {
                println("Authorization password " + password
                        + " does not match account " + accountId);
                exchange.setResponseCode(401);
                exchange.getResponseHeaders().put(Headers.WWW_AUTHENTICATE, "Basic realm=test");

                return;
            }

            if (TRIGGER_TIMEOUT && requestIndex == 2) {
                println("Http server trigerring socket timeout, sleeping");
                try {
                    Thread.sleep(READ_TIMEOUT + 1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt(); // sweep checked exception under the rug
                }
            }

            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
            exchange.getResponseSender().send("Hello World");
            println("Http server returning 200 for server request " + requestIndex);
        }
    }
}
