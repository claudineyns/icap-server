package br.eti.claudiney.icap.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Daemon {

	public static void main(String[] args) throws IOException {
		
		new Daemon().start();
		
	}
	
	private void start() throws IOException {
		
		ServerSocket server = new ServerSocket(1344);
		
		System.out.println("### SERVER ### Ready to listen!");
		
		while(true) {
			Socket client = null;
			try {
				client = server.accept();
			} catch(IOException e) {
				e.printStackTrace();
				break;
			}
			new Thread(new ClientHandler(client)).start();
		}
		
		server.close();
		
	}
	
}
