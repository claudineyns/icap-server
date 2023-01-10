package io.github.rfc3507;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.logging.Logger;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import io.github.rfc3507.server.Worker;

@TestInstance(Lifecycle.PER_CLASS)
public class TestCase {
    final Logger logger = Logger.getLogger(getClass().getSimpleName());

    Worker worker;

    static final int port = 50000 + new Random().nextInt(5000);

    @BeforeAll
    void startup() throws Exception {
        System.setProperty("testMode", "true");
        System.setProperty("app.service.port", Integer.toString(port));

        worker = new Worker();
        worker.start();

        Thread.sleep(1000);
    }

    @Test
    public void optionsTest() throws Exception {

        final String payload = "OPTIONS icap://localhost/${PLACEHOLDER} ICAP/1.1\r\n"
                + "Host: localhost\r\n"
                + "User-Agent: Icap-Client/1.0\r\n"
                + "Encapsulated: null-body=0\r\n"
                + "\r\n";

        final Inet4Address address = (Inet4Address) Inet4Address.getByName("localhost");
        final InetSocketAddress socketAddress = new InetSocketAddress(address, port);

        final String[] services = { "info", "echo", "virus_scan" };

        for (final String service : services) {
            logger.info(String.format("[INFO] Options for service %s", service));

            try (final Socket socket = new Socket()) {

                final int read_timeout = 2000;
                socket.setSoTimeout(read_timeout);

                final int connect_timeout = 5000;
                socket.connect(socketAddress, connect_timeout);

                final OutputStream os = socket.getOutputStream();
                final InputStream is = socket.getInputStream();

                os.write(payload.replace("${PLACEHOLDER}", service).getBytes(StandardCharsets.US_ASCII));
                os.flush();

                final StringBuilder response = new StringBuilder("");
                int reader = -1;
                try {
                    while ((reader = is.read()) != -1) {
                        response.append((char) reader);
                    }
                } catch (SocketTimeoutException e) {
                    /***/
                }

                logger.info(String.format("[INFO]%n%s", response.toString()));

                Assertions.assertTrue(response.toString().startsWith("ICAP/1.0 200 "), () -> "Expected status of 200");
            }
        }
    }

    @Test
    public void infoTest() throws Exception {

        final String payload = "RESPMOD icap://localhost/info ICAP/1.1\r\n"
                + "Host: localhost\r\n"
                + "User-Agent: Icap-Client/1.0\r\n"
                + "Encapsulated: null-body=0\r\n"
                + "\r\n";

        logger.info(String.format("[INFO] %s%n", payload));

        final Inet4Address address = (Inet4Address) Inet4Address.getByName("localhost");
        final InetSocketAddress socketAddress = new InetSocketAddress(address, port);

        final StringBuilder response = new StringBuilder("");

        try (final Socket socket = new Socket()) {

            final int read_timeout = 2000;
            socket.setSoTimeout(read_timeout);

            final int connect_timeout = 5000;
            socket.connect(socketAddress, connect_timeout);

            final OutputStream os = socket.getOutputStream();
            final InputStream is = socket.getInputStream();

            os.write(payload.getBytes(StandardCharsets.US_ASCII));
            os.flush();

            int reader = -1;
            try {
                while ((reader = is.read()) != -1) {
                    response.append((char) reader);
                }
            } catch (SocketTimeoutException e) {
                /***/
            }

            System.out.print(String.format("[INFO]%n%s%n", response.toString()));
        }

        Assertions.assertTrue(response.toString().startsWith("ICAP/1.0 200 "), () -> "Expected status of 200");
    }

    @Test
    public void echoTest() throws Exception {
        final String data = "Hi, there!";
        final byte[] body = data.getBytes(StandardCharsets.US_ASCII);

        final String payload = "REQMOD icap://localhost/echo ICAP/1.1\r\n"
                + "Host: localhost\r\n"
                + "User-Agent: Icap-Client/1.0\r\n"
                + "Allow: 204\r\n"
                + "Encapsulated: req-hdr=0, req-body=0\r\n"
                + "\r\n"
                + Integer.toHexString(body.length) + "\r\n"
                + data + "\r\n"
                + "0; ieof\r\n\r\n";

        logger.info(String.format("[INFO] %s%n", payload));

        final Inet4Address address = (Inet4Address) Inet4Address.getByName("localhost");
        final InetSocketAddress socketAddress = new InetSocketAddress(address, port);

        final StringBuilder response = new StringBuilder("");

        try (final Socket socket = new Socket()) {

            final int read_timeout = 2000;
            socket.setSoTimeout(read_timeout);

            final int connect_timeout = 5000;
            socket.connect(socketAddress, connect_timeout);

            final OutputStream os = socket.getOutputStream();
            final InputStream is = socket.getInputStream();

            os.write(payload.getBytes(StandardCharsets.US_ASCII));
            os.flush();

            int reader = -1;
            try {
                while ((reader = is.read()) != -1) {
                    response.append((char) reader);
                }
            } catch (SocketTimeoutException e) {
                /***/
            }

            System.out.print(String.format("[INFO]%n%s%n", response.toString()));
        }

        Assertions.assertTrue(response.toString().startsWith("ICAP/1.0 200 "), () -> "Expected status of 200");
    }

    @Test
    public void virusScanTest() throws Exception {
        final String data = "Threat";
        final byte[] body = data.getBytes(StandardCharsets.US_ASCII);

        final String payload = "REQMOD icap://localhost/virus_scan ICAP/1.1\r\n"
                + "Host: localhost\r\n"
                + "User-Agent: Icap-Client/1.0\r\n"
                + "Allow: 204\r\n"
                + "Encapsulated: req-hdr=0, req-body=0\r\n"
                + "\r\n"
                + Integer.toHexString(body.length) + "\r\n"
                + data + "\r\n"
                + "0; ieof\r\n\r\n";

        logger.info(String.format("[INFO] %s%n", payload));

        final Inet4Address address = (Inet4Address) Inet4Address.getByName("localhost");
        final InetSocketAddress socketAddress = new InetSocketAddress(address, port);

        final String[] oses = { "linux", "windows" };

        for (final String ops : oses) {
            System.setProperty("test.os.name", ops);

            try (final Socket socket = new Socket()) {
                final StringBuilder response = new StringBuilder("");

                final int read_timeout = 2000;
                socket.setSoTimeout(read_timeout);

                final int connect_timeout = 5000;
                socket.connect(socketAddress, connect_timeout);

                final OutputStream os = socket.getOutputStream();
                final InputStream is = socket.getInputStream();

                os.write(payload.getBytes(StandardCharsets.US_ASCII));
                os.flush();

                int reader = -1;
                try {
                    while ((reader = is.read()) != -1) {
                        response.append((char) reader);
                    }
                } catch (SocketTimeoutException e) {
                    /***/
                }

                System.out.print(String.format("[INFO]%n%s%n", response.toString()));

                Assertions.assertTrue(response.toString().startsWith("ICAP/1.0 200 "), () -> "Expected status of 200");
            }
        }

        System.clearProperty("test.os.name");
    }

    @AfterAll
    void terminate() throws Exception {
        worker.stop();
    }

}
