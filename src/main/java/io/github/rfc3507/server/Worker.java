package io.github.rfc3507.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Logger;

public class Worker {

	public static void main(String[] args) throws IOException {
		new Worker().start();
	}
	
	private final Logger logger = Logger.getGlobal();
	
	private ServerSocket server;
	
	private void start() throws IOException {
		
		this.server = new ServerSocket(1344);
		
		final Thread shutdown = new Thread(()->{
			try { server.close(); } catch(IOException e) {}
			logger.info("[ICAP-SERVER] Service terminated.");
		});

		Runtime.getRuntime().addShutdownHook(shutdown);
		
		logger.info("[ICAP-SERVER] Listening on port 1344");
		
		while(true) {
			Socket client = null;
			try {
				client = server.accept();
				Logger.getGlobal().info("[ICAP-SERVER] Connection received!");
			} catch(IOException e) {
				e.printStackTrace();
				break;
			}
			new Thread(new ClientHandler(client)).start();
		}
		
	}
	
}
