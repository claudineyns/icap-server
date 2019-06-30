package net.rfc3507.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Logger;

public class Daemon {

	public static void main(String[] args) throws IOException {
		
		new Daemon().start();
		
	}
	
	private void start() throws IOException {
		
		ServerSocket server = new ServerSocket(1344);
		
		Logger.getGlobal().info("[ICAP-SERVER] Listening on port 1344");
		
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
		
		server.close();
		
	}
	
}
