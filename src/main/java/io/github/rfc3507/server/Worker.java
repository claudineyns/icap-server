package io.github.rfc3507.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Logger;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;

public class Worker {

	public static void main(String[] args) throws IOException {
		new Worker().start();
	}
	
	private final Logger logger = Logger.getGlobal();
	
	private ServerSocket server;
	
	private void start() throws IOException {		
		final Thread shutdown = new Thread(()->{
			try { server.close(); } catch(IOException e) {}
			logger.info("[ICAP-SERVER] Service terminated.");
		});
		Runtime.getRuntime().addShutdownHook(shutdown);

		Executors.newSingleThreadExecutor().submit(() -> startService());
	}

	private void startService() {
		try {
			listen();
		} catch(IOException e) {
			stopService();
		}
	}

	private void stopService() {
		try {
			server.close();
		} catch(IOException e) {}
	}

	private void listen() throws IOException {

		final String servicePort = Optional
			.ofNullable(System.getenv("APP_SERVICE_PORT"))
			.orElse("1344");

		this.server = new ServerSocket(Integer.parseInt(servicePort));
		
		logger.info("[ICAP-SERVER] Listening on port "+servicePort);
		
		while(true) {
			Socket client = null;
			try {
				client = server.accept();
				Logger.getGlobal().info("[ICAP-SERVER] Connection received!");
			} catch(IOException e) {
				break;
			}

			CompletableFuture.runAsync(new ClientHandler(client));
		}
		
	}
	
}
