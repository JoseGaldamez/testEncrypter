import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.*;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class TestEncryptor {

    private static PublicKey publicKey;
    private static PrivateKey privateKey;




    public static void main(String[] args) {

        try {



            // Configure http server
            HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

            // Endpoints
            server.createContext("/alive", new AliveHandler());
            server.createContext("/encrypt", new EncryptHandler());
            server.createContext("/decrypt", new DecryptHandler());

            // Run server
            server.setExecutor(null);
            System.out.println("Server running on port 8080...");
            server.start();
        } catch (IOException ioException) {
            System.out.println("Error creating the server: " + ioException.getMessage());
        }
    }





    // Handler endpoint /alive
    static class AliveHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "OK";
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }






    // Handler to endpoint /decrypt
    static  class DecryptHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {

            try {

                if("POST".equalsIgnoreCase(exchange.getRequestMethod())){
                    String encryptedText = new String(exchange.getRequestBody().readAllBytes());

                    String decryptedText = EncryptService.DecryptContentRSA(encryptedText);

                    exchange.sendResponseHeaders(200, decryptedText.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(decryptedText.getBytes());
                    os.close();

                } else {
                    exchange.sendResponseHeaders(405, -1);
                }
            } catch (Exception e){
                System.out.println(Arrays.toString(e.getStackTrace()));
                String invalidFormat = "Invalid format";
                exchange.sendResponseHeaders(500, invalidFormat.length());
                OutputStream os = exchange.getResponseBody();
                os.write(invalidFormat.getBytes());
                os.close();
            }

        }
    }








    // Handler to endpoint /encrypt
    static class EncryptHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if ("POST".equalsIgnoreCase(exchange.getRequestMethod())){
                    String plainText = new String(exchange.getRequestBody().readAllBytes());

                    // Encrypt right here
                    String encryptedText = EncryptService.EncryptContentRSA(plainText);

                    exchange.sendResponseHeaders(200, encryptedText.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(encryptedText.getBytes());
                    os.close();

                } else {
                    exchange.sendResponseHeaders(405, -1);
                }
            } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                     BadPaddingException | InvalidKeyException ioException){
                System.out.println(ioException.getMessage());

                String responseText = "Error on server";

                exchange.sendResponseHeaders(500, responseText.length());
                OutputStream os = exchange.getResponseBody();
                os.write(responseText.getBytes());
                os.close();
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
        }
    }

}
