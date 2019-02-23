package br.eti.claudiney.icap.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ClientHandler implements Runnable {
	
	private Socket client;
	
	private InputStream in;
	private OutputStream out;
	private String serverName;
	
	public ClientHandler(Socket c) {
		this.client = c;
		try {
			serverName = Inet4Address.getLocalHost().getHostName();
		} catch(IOException e) {
			System.err.println("### SERVER ### Startup [WARNING] " +  e.getMessage());
			serverName = "localhost";
		}
		serverName += ".claudiney.eti.br";
	}

	@Override
	public void run() {
		
		try {
			in = client.getInputStream();
			out = client.getOutputStream();
			handle();
			out.close();
			in.close();
		} catch(IOException e) {
			System.err.println("### SERVER ### " + e.getMessage());
		}
		
		try {
			client.close();
		} catch(IOException e) {
			System.err.println("### SERVER ### " + e.getMessage());
		}
		
	}
	
	private static final String OPTIONS = "OPTIONS";
	private static final String REQMOD  = "REQMOD";
	private static final String RESPMOD = "RESPMOD";
	
	private String methodInProgress = null;
	private String serviceInProgress = null;
	
	private String encapsulatedHeader = null;
	private String previewHeader = null;
	
	private ByteArrayOutputStream httpRequestHeaders = null;
	private ByteArrayOutputStream httpRequestBody = null;
	private ByteArrayOutputStream httpResponseHeaders = null;
	private ByteArrayOutputStream httpResponseBody = null;
	
	private void handle() throws IOException {

		while(true) {
			
			httpRequestHeaders = new ByteArrayOutputStream();
			httpRequestBody = new ByteArrayOutputStream();
			httpResponseHeaders = new ByteArrayOutputStream();
			httpResponseBody = new ByteArrayOutputStream();
			
			methodInProgress = null;
			
			startHandleIcapRequest();
			if( methodInProgress != null ) {
				continueHandleIcapRequest();
			}
			if( OPTIONS.equals(methodInProgress) ) {
				continue;
			}
			break;
		}
		
	}
	
	private void startHandleIcapRequest() throws IOException {
		
		ByteArrayOutputStream cache = new ByteArrayOutputStream();
		
		int reader = -1;
		while( (reader = in.read()) != -1) {
			
			cache.write(reader);
			
			byte[] memory = cache.toByteArray();
			if( memory.length >= 4 ) {
				if(    memory[memory.length-4] == '\r' 
					&& memory[memory.length-3] == '\n' 
					&& memory[memory.length-2] == '\r' 
					&& memory[memory.length-1] == '\n' ) {
					
					info("### (SERVER: RECEIVE) ### ICAP REQUEST\n"+new String(memory));
					
					analyseRequestHeader(memory);
					break;
					
				}
			}
			
		}
		
	}
	
	private void continueHandleIcapRequest() throws IOException {
		
		extractEncapsulatedPayloads();
		
		if( REQMOD.equals(methodInProgress) ) {
			continueRequestModification();
		} else if( RESPMOD.equals(methodInProgress) ) {
			continueResponseModification();
		}
		
	}
	
	private void extractEncapsulatedPayloads() throws IOException {

        int httpRequestHeaderSize = 0;
        int httpResponseHeaderSize = 0;
        
        String lastOffsetLabel = "";
        
        int lastOffsetValue = 0;
        
        String[] encapsulatedValues = encapsulatedHeader.split(",");
        
        for(String offset: encapsulatedValues) {
        	
        	String offsetParser[] = offset.split("=");
        	
        	String offsetLabel = offsetParser[0].trim();
        	
        	int offsetValue = Integer.parseInt(offsetParser[1].trim());
        	
        	switch(lastOffsetLabel) {
        		
	        	case "req-hdr":
	        		httpRequestHeaderSize = (offsetValue - lastOffsetValue);
	        		break;
	        		
	        	case "res-hdr":
	        		httpResponseHeaderSize = (offsetValue - lastOffsetValue);
	        		break;
	        		
        	}
        	
        	lastOffsetLabel = offsetLabel;
        	lastOffsetValue = offsetValue;
        	
        }
        
        byte[] parseContent = null;
        
        if( httpRequestHeaderSize > 0 ) {
        	parseContent = new byte[httpRequestHeaderSize];
        	in.read(parseContent);
        	info("### (SERVER: RECEIVE) ### HTTP REQUEST HEADER\n"+new String(parseContent));
        	httpRequestHeaders.write(parseContent);
        }
        
        if( httpResponseHeaderSize > 0 ) {
        	parseContent = new byte[httpResponseHeaderSize];
        	in.read(parseContent);
        	info("### (SERVER: RECEIVE) ### HTTP RESPONSE HEADER\n"+new String(parseContent));
        	httpResponseHeaders.write(parseContent);
        }
		
		if( "req-body".equals(lastOffsetLabel) ) {
			readBody(httpRequestBody);
			info("### (SERVER: RECEIVE) ### HTTP REQUEST BODY\n"+new String(httpRequestBody.toByteArray()));
		}
		
		if( "res-body".equals(lastOffsetLabel) ) {
			readBody(httpResponseBody); 
			info("### (SERVER: RECEIVE) HTTP RESPONSE BODY ###\n"+new String(httpResponseBody.toByteArray()));
		}
		
	}
	
	private void readBody(OutputStream out) throws IOException {
        
        boolean previewIsEnough = false;
		if( previewHeader != null ) {
			
			int contentPreview = Integer.parseInt(previewHeader);
			if(contentPreview > 0) {
				previewIsEnough = extractBody(out);
			}
			
			if( ! previewIsEnough ){
				sendContinue();
			}
			
		}
		
		if( !previewIsEnough ) {
			// Read remaining body content
			extractBody(out);
		}
		
	}
	
	private boolean extractBody(OutputStream out) throws IOException {
		
		StringBuilder line = new StringBuilder("");
		
		int mark[] = new int[11];
		int amountToRead = -1;
		
		while(true) {
			
			int reader = in.read();
			
			shift(mark);
			
			mark[10] = reader;
			
			if( reader == '\r'
					|| (reader != '\n' && ! isHexDigit(reader)) ) {
				continue;
			}
			
			if(    mark[6]  == '0'
				&& mark[7]  == '\r'
				&& mark[8]  == '\n'
				&& mark[9]  == '\r' 
				&& mark[10] == '\n' ) {
				
				return false;
				
			}
			
			if(    mark[0 ] == '0'
				&& mark[1 ] == ';'
				&& mark[2 ] == ' '
				&& mark[3 ] == 'i' 
				&& mark[4 ] == 'e'
				&& mark[5 ] == 'o'
				&& mark[6 ] == 'f'
				&& mark[7 ] == '\r'
				&& mark[8 ] == '\n'
				&& mark[9 ] == '\r'
				&& mark[10] == '\n' ) {
				
				return true;
				
			}
			
			if(    mark[9 ] == '\r'
				&& mark[10] == '\n' ) {
				
				amountToRead = Integer.parseInt(line.toString(), 16);
				
				if( amountToRead > 0 ) {
					byte[] cache = new byte[amountToRead];
					in.read(cache);
					out.write(cache);
					in.skip(2); // \r\n
					reset(mark);
				}
				
				line = new StringBuilder("");
				
				continue;
				
			}
			
			line.append((char)reader);
			
		}
		
	}
	
	private void analyseRequestHeader(byte[] memory) throws IOException {

		String data = new String(memory);

		String[] entries = data.split("\\r\\n");
		
		if( entries.length == 0 ) {
			sendBadRequest("Invalid ICAP Request");
			return;
		}
		
		String methodLine = entries[0];
		String methodLine2 = methodLine.toUpperCase();
		
		if( ! methodLine2.startsWith(OPTIONS) 
				&& ! methodLine2.startsWith(REQMOD) 
				&& ! methodLine2.startsWith(RESPMOD) ) {
			sendMethodNotAllowed();
			return;
		}
		
		if( ! methodLine2.startsWith(OPTIONS+" ") 
				&& ! methodLine2.startsWith(REQMOD+" ") 
				&& ! methodLine2.startsWith(RESPMOD+" ") ) {
			sendBadRequest("Invalid ICAP Method Sintax");
			return;
		}
		
		String[] methodContent = methodLine.split("\\s");
		
		if( methodContent.length != 3 ) {
			sendBadRequest("Invalid ICAP Method Sintax");
			return;
		}
		
		String uri = methodContent[1];
		String[] uriParser = validateURI(uri);
		
		if( uriParser == null ) {
			sendBadRequest("Invalid ICAP URI");
			return;
		}
		
		for(int i = 1; i < entries.length; ++i ) {
			String icapHeader = entries[i]; 
			if( icapHeader.toLowerCase().startsWith("encapsulated:") ) {
				encapsulatedHeader = icapHeader.substring(icapHeader.indexOf(':')+1).trim();
				continue;
			}
			if( icapHeader.toLowerCase().startsWith("preview:") ) {
				previewHeader = icapHeader.substring(icapHeader.indexOf(':')+1).trim();
				continue;
			}
		}
		
		if( encapsulatedHeader == null ) {
			sendBadRequest("Invalid ICAP Requirements: <Encapsulated> Header not found");
			return;
		}
		
		if( previewHeader != null ) {
			try {
				Integer.parseInt(previewHeader);
			} catch(NumberFormatException e){
				sendBadRequest("Invalid ICAP Sintax: <Preview> Header not numeric");
				return;
			}
		}
		
		if( methodLine2.startsWith(OPTIONS) ) {
			
			handleOptions(entries, uriParser);
			
		} else if( methodLine2.startsWith(REQMOD) ) {
			
			handleRequestModification(entries, uriParser);
			
		} else if( methodLine2.startsWith(RESPMOD) ) {
			
			handleResponseModification(entries, uriParser);
			
		}
		
	}
	
	private void finishResponse() throws IOException {
		out.write("0\r\n".getBytes());
	}
	
	private void sendCloseConnection() throws IOException {
		out.write("Connection: close\r\n".getBytes());
		out.write(("Encapsulated: null-body=0\r\n").getBytes());
		out.write("\r\n".getBytes());
	}
	
	private void sendContinue() throws IOException {
		out.write("ICAP/1.0 100 Continue\r\n".getBytes());
		out.write("\r\n".getBytes());
	}
	
	private void sendBadRequest(String cause) throws IOException {
		out.write("ICAP/1.0 400 Bad request\r\n".getBytes());
		if( cause == null ) {
			sendCloseConnection();
		} else {
			out.write("Connection: close\r\n".getBytes());
			out.write(("Encapsulated: opt-body=0\r\n").getBytes());
			out.write("\r\n".getBytes());
			out.write((Integer.toHexString(cause.length())+"\r\n").getBytes());
			out.write((cause+"\r\n").getBytes());
			finishResponse();
		}
	}
	
	private void sendServiceNotFound() throws IOException {
		out.write("ICAP/1.0 404 Service not found\r\n".getBytes());
		sendCloseConnection();
	}
	
	private void sendMethodNotAllowed() throws IOException {
		out.write("ICAP/1.0 405 Method not allowed\r\n".getBytes());
		sendCloseConnection();
	}
	
	private String[] validateURI(String uri) throws IOException {
		
		Pattern uriPattern = Pattern.compile("icap:\\/\\/(.*)(\\/.*)");
		Matcher uriMatcher = uriPattern.matcher(uri);
		
		if( ! uriMatcher.matches() ) {
			return null;
		}
		
		if( uriMatcher.groupCount() > 1 ) {
			return new String[] { uriMatcher.group(1), uriMatcher.group(2).substring(1) };
		} else {
			return new String[] { uriMatcher.group(1), "" };
		}
		
	}
	
	private void handleOptions(String[] entries, String[] uriParser) throws IOException {
		
		String service = uriParser[1];
		String service2 = service.toLowerCase();
		
		if( !service2.startsWith("info") 
				&& !service2.startsWith("echo") 
				&& !service2.startsWith("virus_scan") ) {
			
			sendServiceNotFound();
			return;
			
		}
			
		String date = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss Z", Locale.US).format(new Date());
		
		out.write(("ICAP/1.0 200 OK\r\n").getBytes());
		out.write(("Date: "+date+"\r\n").getBytes());
		out.write(("Server: ICAP-Java-Server/1.0\r\n").getBytes());
		
		if( service2.startsWith("info")) {
			out.write(("Methods: "+RESPMOD+"\r\n").getBytes());
		} else if( service2.startsWith("echo")) {
			out.write(("Methods: "+REQMOD+", "+RESPMOD+"\r\n").getBytes());
		} else if( service2.startsWith("virus_scan")) {
			out.write(("Methods: "+REQMOD+", "+RESPMOD+"\r\n").getBytes());
		}
		
		out.write(("Service: Java Tech Server 1.0\r\n").getBytes());
		out.write(("ISTag:\"ALPHA-B123456-GAMA\"\r\n").getBytes());
		out.write(("Allow: 204\r\n").getBytes());
		out.write(("Preview: 1024\r\n").getBytes());
		out.write(("Transfer-Preview: *\r\n").getBytes());
		out.write(("Encapsulated: null-body=0\r\n").getBytes());
		out.write(("\r\n").getBytes());
		
		methodInProgress = OPTIONS;
		
	}
	
	private void handleRequestModification(String[] entries, String[] uriParser) throws IOException {
		
		String service = uriParser[1];
		String service2 = service.toLowerCase();
		
		if( !service2.startsWith("echo") 
				&& !service2.startsWith("virus_scan") ) {
			
			sendMethodNotAllowed();
			return;
			
		}
		
		serviceInProgress = service2;
		methodInProgress = REQMOD;
		
	}
	
	private void handleResponseModification(String[] entries, String[] uriParser) throws IOException {
		
		String service = uriParser[1];
		String service2 = service.toLowerCase();
		
		if( !service2.startsWith("info")
				&& !service2.startsWith("echo")
				&& !service2.startsWith("virus_scan") ) {
			
			sendMethodNotAllowed();
			return;
			
		}
		
		serviceInProgress = service2;
		methodInProgress = RESPMOD;
		
	}
	
	private void continueRequestModification() throws IOException {
		
		String date = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss Z", Locale.US).format(new Date());
		
		if( httpRequestBody.size() == 0 && httpResponseBody.size() == 0 ) {
			out.write(("ICAP/1.0 204 No Content\r\n").getBytes());
		} else {
			out.write(("ICAP/1.0 200 OK\r\n").getBytes());
		}
		
		out.write(("Date: "+date+"\r\n").getBytes());
		out.write(("Server: ICAP-Java-Server/1.0\r\n").getBytes());
		out.write(("ISTag:\"ALPHA-B123456-GAMA\"\r\n").getBytes());
		out.write(("Connection: close\r\n").getBytes());
		
		if( serviceInProgress.startsWith("echo") ) {
			completeHandleEcho();
		} else if( serviceInProgress.startsWith("virus_scan") ) {
			completeHandleVirusScan();
		}
		
	}
	
	private void continueResponseModification() throws IOException {
		
		String date = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss Z", Locale.US).format(new Date());
		
		out.write(("ICAP/1.0 200 OK\r\n").getBytes());
		out.write(("Date: "+date+"\r\n").getBytes());
		out.write(("Server: ICAP-Java-Server/1.0\r\n").getBytes());
		out.write(("ISTag:\"ALPHA-B123456-GAMA\"\r\n").getBytes());
		out.write(("Connection: close\r\n").getBytes());
		
		if( serviceInProgress.startsWith("info") ) {
			completeHandleInfo(date);
		} else if( serviceInProgress.startsWith("echo") ) {
			completeHandleEcho();
		} else if( serviceInProgress.startsWith("virus_scan") ) {
			completeHandleVirusScan();
		}
		
	}
	
	private void completeHandleInfo(String date) throws IOException {
		
		StringBuilder httpResponseBody = new StringBuilder();
		httpResponseBody.append("OPTIONS icap://"+serverName+" ICAP/1.0\r\n");
		httpResponseBody.append("OPTIONS icap://"+serverName+"/info ICAP/1.0\r\n");
		httpResponseBody.append("OPTIONS icap://"+serverName+"/echo ICAP/1.0\r\n");
		httpResponseBody.append("OPTIONS icap://"+serverName+"/virus_scan ICAP/1.0\r\n");
		httpResponseBody.append("REQMODE icap://"+serverName+"/echo ICAP/1.0\r\n");
		httpResponseBody.append("REQMODE icap://"+serverName+"/virus_scan ICAP/1.0\r\n");
		httpResponseBody.append("RESPMODE icap://"+serverName+"/info ICAP/1.0\r\n");
		httpResponseBody.append("RESPMODE icap://"+serverName+"/echo ICAP/1.0\r\n");
		httpResponseBody.append("RESPMODE icap://"+serverName+"/virus_scan ICAP/1.0\r\n");
		httpResponseBody.append("\r\n");
		
		StringBuilder chunkedBody = new StringBuilder()
				.append( Integer.toHexString(httpResponseBody.length()) )
				.append("\r\n")
				.append(httpResponseBody);
		
		StringBuilder httpResponseHeader = new StringBuilder();
		
		httpResponseHeader.append("HTTP/1.1 200 OK\r\n");
		httpResponseHeader.append(("Date: "+date+"\r\n"));
		httpResponseHeader.append(("Server: localhost\r\n"));
		httpResponseHeader.append(("Content-Type: text/plain\r\n"));
		httpResponseHeader.append(("Content-Length: "+httpResponseBody.length()+"\r\n"));
		httpResponseHeader.append(("Via: 1.0 "+serverName+"\r\n"));
		httpResponseHeader.append("\r\n");
		
		out.write(("Encapsulated: res-hdr=0, res-body="+httpResponseHeader.length()+"\r\n").getBytes());
		out.write("\r\n".getBytes());
		
		out.write(httpResponseHeader.toString().getBytes());
		out.write(chunkedBody.toString().getBytes());
		
	}
	
	private void completeHandleEcho() throws IOException {
		
		out.write(("Encapsulated: "+encapsulatedHeader+"\r\n").getBytes());
		out.write("\r\n".getBytes());
		
		boolean eof = false;
		if(httpRequestHeaders.size() > 0) {
			eof = true;
			out.write(httpRequestHeaders.toByteArray());
		}
		
		if(httpRequestBody.size() > 0) {
			eof = true;
			out.write( (Integer.toHexString(httpRequestBody.size())+"\r\n").getBytes()  );
			out.write(httpRequestBody.toByteArray());
			out.write("\r\n".getBytes());
		}
		
		if(httpResponseHeaders.size() > 0) {
			eof = true;
			out.write(httpResponseHeaders.toByteArray());
		}
		
		if(httpResponseBody.size() > 0) {
			eof = true;
			out.write( (Integer.toHexString(httpResponseBody.size())+"\r\n").getBytes()  );
			out.write(httpResponseBody.toByteArray());
			out.write("\r\n".getBytes());
		}
		
		if(eof) {
			finishResponse();
		}
		
	}
	
	private void completeHandleVirusScan() throws IOException {
		
	}
	
	private void info(String message) {
		Logger.getGlobal().info(message);
	}
	
	private static void reset( int[]c ){
		for(int i = 0; i < c.length; ++i) c[i]=-1;
	}
	
	private static void shift( int[]c ) {
		for( int i = 1; i < c.length; ++i ) c[i-1] = c[i];
	}
	
	private static boolean isHexDigit(char ch) {
		
		if(Character.isDigit(ch))  return true;
		if(ch >= 'A' && ch <= 'F') return true;
		if(ch >= 'a' && ch <= 'f') return true;
		
		return false;
		
	}
	
	private static boolean isHexDigit(int codePoint) {
		return isHexDigit((char)codePoint);
	}
	
	public static void main(String[] args) throws Exception {
		Daemon.main(args);
	}
	
}
