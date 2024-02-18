package io.github.rfc3507.server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.github.rfc3507.av.clamav.ClamAVCore;
import io.github.rfc3507.av.clamav.ClamAVResponse;
import io.github.rfc3507.av.windowsdefender.WindowsDefenderAntivirus;
import io.github.rfc3507.av.windowsdefender.WindowsDefenderResponse;

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
			warning("\n### SERVER ### [Startup] [WARNING]\n" +  e.getMessage());
			serverName = "localhost";
		}
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
			warning("\n### SERVER ### [Cleanup] [WARNING] General error:\n" + e.getMessage());
		}

		try {
			client.close();
		} catch(IOException e) {
			warning("\n### SERVER ### [Cleanup] [WARNING] General error:\n" + e.getMessage());
		}

		info("\n### SERVER ### [Cleanup] [INFO] Client request completed.\n");

	}

	private static final String OPTIONS = "OPTIONS";
	private static final String REQMOD  = "REQMOD";
	private static final String RESPMOD = "RESPMOD";

	private String methodInProgress = null;
	private String serviceInProgress = null;

	private String encapsulatedHeader = null;
	private String previewHeader = null;

	private ByteArrayOutputStream httpRequestHeaders = new ByteArrayOutputStream();
	private ByteArrayOutputStream httpRequestBody = new ByteArrayOutputStream();
	private ByteArrayOutputStream httpResponseHeaders = new ByteArrayOutputStream();
	private ByteArrayOutputStream httpResponseBody = new ByteArrayOutputStream();

	private void handle() throws IOException {

		while(true) {

			httpRequestHeaders.reset();
			httpRequestBody.reset();
			httpResponseHeaders.reset();
			httpResponseBody.reset();

			methodInProgress = null;

			try {
				startHandleIcapRequest();
				if( methodInProgress != null ) {
					continueHandleIcapRequest();
				}
				out.flush();
			} catch(IOException e) {
				e.printStackTrace();
				break;
			} catch(Exception e) {
				sendServerError(e.getMessage());
			}

			if( OPTIONS.equals(methodInProgress) ) {
				continue;
			}
			break;
		}

	}

	private void startHandleIcapRequest() throws Exception {

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

					analyseRequestHeader(memory);
					break;

				}
			}

		}

	}

	private void continueHandleIcapRequest() throws Exception {

		extractEncapsulatedPayloads();

		if( REQMOD.equals(methodInProgress) ) {
			continueRequestModification();
		} else if( RESPMOD.equals(methodInProgress) ) {
			continueResponseModification();
		}

	}

	private void extractEncapsulatedPayloads() throws Exception {

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
        	readStream(parseContent);
        	httpRequestHeaders.write(parseContent);
        }

        if( httpResponseHeaderSize > 0 ) {
        	parseContent = new byte[httpResponseHeaderSize];
        	readStream(parseContent);
        	httpResponseHeaders.write(parseContent);
        }

		if( "req-body".equals(lastOffsetLabel) ) {
			readBody(httpRequestBody);
		}

		if( "res-body".equals(lastOffsetLabel) ) {
			readBody(httpResponseBody);
		}

	}

	private void readBody(OutputStream out) throws Exception {

        	boolean previewIsEnough = false;

		if( previewHeader != null ) {
			/*
			 * Read preview payload
			 */
			int contentPreview = Integer.parseInt(previewHeader);
			previewIsEnough = extractBody(out, contentPreview);
			if( ! previewIsEnough ){
				sendContinue();
			}
		}

		if( !previewIsEnough ) {
			/*
			 * Read remaining body payload
			 */
			extractBody(out, -1);
		}

	}

	private boolean extractBody(OutputStream out, int previewSize) throws Exception {

		ByteArrayOutputStream backupDebug = new ByteArrayOutputStream(); 

		StringBuilder line = new StringBuilder("");

		byte[] cache = null;

		int mark[] = new int[2];
		reset(mark);

		StringBuilder control = new StringBuilder("");

		while(true) {

			int reader = in.read();
			shift(mark);
			mark[1] = reader;

			backupDebug.write(reader);

			control.append((char)reader);

			if( reader == ';' ) {
				continue;
			}

			if( reader == ' ' || reader == 'i' ){
				continue;
			}

			if( reader == 'e' ) {
				if(control.toString().equals("0; ie")) {
					continue;
				}
			}

			if( reader == 'f' ) {
				if(control.toString().equals("0; ieof")) {
					continue;
				}
			}

			if( reader == '\r' ) {
				continue;
			}

			if(    mark[0] == '\r'
				&& mark[1] == '\n' ) {

				if( control.toString().equals("0; ieof\r\n\r\n") ) {
					return true;
				}

				if( control.toString().startsWith("0; ieof") ) {
					continue;
				}

				if( line.length() == 0 ) {
					return false;
				}

				int amountRead = Integer.parseInt(line.toString(), 16);

				if(amountRead > 0) {
					cache = new byte[amountRead];
					readStream(cache);
					out.write(cache);
					backupDebug.write(cache);
				}

				int cr = -1, lf = -1;
				cr = in.read(); lf = in.read();
				backupDebug.write(cr); backupDebug.write(lf);

				if( cr != '\r' || lf != '\n' ) {
					throw new Exception("Error reading end of chunk");
				}

				if( amountRead > 0 ) {
					control = new StringBuilder("");
				} else {
					control.append((char)cr);
					control.append((char)lf);
				}

				if( control.toString().equals("0\r\n\r\n")) {
					return false;
				}

				line = new StringBuilder("");

				continue;

			}

			line.append((char)reader);

		}

	}

	private void analyseRequestHeader(byte[] memory) throws Exception {

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
			if( icapHeader.toLowerCase().startsWith("host:") ) {
				serverName = icapHeader.substring(icapHeader.indexOf(':')+1).trim();
				continue;
			}

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
		out.write("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
	}

	private void sendCloseConnection() throws IOException {
		out.write("Connection: close\r\n".getBytes(StandardCharsets.US_ASCII));
		out.write(("Encapsulated: null-body=0\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
	}

	private void sendContinue() throws IOException {
		out.write("ICAP/1.0 100 Continue\r\n".getBytes(StandardCharsets.US_ASCII));
		out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
	}

	private void sendBadRequest(String cause) throws IOException {
		out.write("ICAP/1.0 400 Bad request\r\n".getBytes(StandardCharsets.US_ASCII));
		if( cause == null ) {
			sendCloseConnection();
		} else {
			out.write("Connection: close\r\n".getBytes(StandardCharsets.US_ASCII));
			out.write(("Encapsulated: opt-body=0\r\n").getBytes(StandardCharsets.US_ASCII));
			out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
			out.write((Integer.toHexString(cause.length())+"\r\n").getBytes(StandardCharsets.US_ASCII));
			out.write((cause+"\r\n").getBytes(StandardCharsets.US_ASCII));
			finishResponse();
		}
	}

	private void sendServiceNotFound() throws IOException {
		out.write("ICAP/1.0 404 Service not found\r\n".getBytes(StandardCharsets.US_ASCII));
		sendCloseConnection();
	}

	private void sendMethodNotAllowed() throws IOException {
		out.write("ICAP/1.0 405 Method not allowed\r\n".getBytes(StandardCharsets.US_ASCII));
		sendCloseConnection();
	}

	private void sendServerError(String cause) throws IOException {
		out.write("ICAP/1.0 500 Server Error\r\n".getBytes(StandardCharsets.US_ASCII));
		if( cause == null ) {
			sendCloseConnection();
		} else {
			out.write("Connection: close\r\n".getBytes(StandardCharsets.US_ASCII));
			out.write(("Encapsulated: opt-body=0\r\n").getBytes(StandardCharsets.US_ASCII));
			out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
			out.write((Integer.toHexString(cause.length())+"\r\n").getBytes(StandardCharsets.US_ASCII));
			out.write((cause+"\r\n").getBytes(StandardCharsets.US_ASCII));
			finishResponse();
		}
	}

	private String[] validateURI(String uri) {

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

	private void handleOptions(
			String[] entries,
			String[] uriParser) throws Exception {

		String service = uriParser[1];
		String service2 = service.toLowerCase();

		if( !service2.startsWith("info") 
				&& !service2.startsWith("echo") 
				&& !service2.startsWith("virus_scan") ) {

			sendServiceNotFound();
			return;

		}

		String date = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss Z", Locale.US).format(new Date());

		out.write(("ICAP/1.0 200 OK\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write(("Date: "+date+"\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write(("Server: "+serverName+"\r\n").getBytes(StandardCharsets.US_ASCII));

		if( service2.startsWith("info")) {
			out.write(("Methods: "+RESPMOD+"\r\n").getBytes(StandardCharsets.US_ASCII));
		} else if( service2.startsWith("echo")) {
			out.write(("Methods: "+REQMOD+", "+RESPMOD+"\r\n").getBytes(StandardCharsets.US_ASCII));
		} else if( service2.startsWith("virus_scan")) {
			out.write(("Methods: "+REQMOD+", "+RESPMOD+"\r\n").getBytes(StandardCharsets.US_ASCII));
		}

		out.write(("Service: ICAP-Server-Java/1.0\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write(("ISTag:\""+UUID.randomUUID().toString()+"\"\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write(("Allow: 204\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write(("Preview: 0\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write(("Transfer-Complete: *\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write(("Encapsulated: null-body=0\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write(("\r\n").getBytes(StandardCharsets.US_ASCII));

		methodInProgress = OPTIONS;

	}

	private void handleRequestModification(
			String[] entries,
			String[] uriParser) throws Exception {

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

	private void handleResponseModification(
			String[] entries,
			String[] uriParser) throws Exception {

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

	private void continueRequestModification() throws Exception {

		if( serviceInProgress.startsWith("virus_scan") ) {
			findThreatsInPayload();
		}

		String date = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss Z", Locale.US).format(new Date());

		if( serviceInProgress.startsWith("echo") && httpRequestBody.size() == 0 ) {
			out.write(("ICAP/1.0 204 No Content\r\n").getBytes(StandardCharsets.US_ASCII));
		} else {
			out.write(("ICAP/1.0 200 OK\r\n").getBytes(StandardCharsets.US_ASCII));
		}

		out.write(("Date: "+date+"\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write(("Server: "+serverName+"\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write(("ISTag:\"ALPHA-B123456-GAMA\"\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write(("Connection: close\r\n").getBytes(StandardCharsets.US_ASCII));

		if( serviceInProgress.startsWith("echo") ) {
			completeHandleEcho();
		} else if( serviceInProgress.startsWith("virus_scan") ) {
			completeHandleVirusScan();
		}

	}

	private void continueResponseModification() throws Exception {

		if( serviceInProgress.startsWith("virus_scan") ) {
			findThreatsInPayload();
		}

		String date = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss Z", Locale.US).format(new Date());

		if( serviceInProgress.startsWith("echo") && httpResponseBody.size() == 0 ) {
			out.write(("ICAP/1.0 204 No Content\r\n").getBytes(StandardCharsets.US_ASCII));
		} else {
			out.write(("ICAP/1.0 200 OK\r\n").getBytes(StandardCharsets.US_ASCII));
		}

		out.write(("Date: "+date+"\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write(("Server: "+serverName+"\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write(("ISTag: \"ALPHA-B123456-GAMA\"\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write(("Connection: close\r\n").getBytes(StandardCharsets.US_ASCII));

		if( serviceInProgress.startsWith("info") ) {
			completeHandleInfo(date);
		} else if( serviceInProgress.startsWith("echo") ) {
			completeHandleEcho();
		} else if( serviceInProgress.startsWith("virus_scan") ) {
			completeHandleVirusScan();
		}

	}

	private void completeHandleInfo(String date) throws Exception {

		StringBuilder httpResponseBody = new StringBuilder();

		httpResponseBody.append("OPTIONS icap://"+serverName+"/info ICAP/1.0\r\n");
		httpResponseBody.append("OPTIONS icap://"+serverName+"/echo ICAP/1.0\r\n");
		httpResponseBody.append("OPTIONS icap://"+serverName+"/virus_scan ICAP/1.0\r\n");

		httpResponseBody.append("REQMOD icap://"+serverName+"/echo ICAP/1.0\r\n");
		httpResponseBody.append("REQMOD icap://"+serverName+"/virus_scan ICAP/1.0\r\n");

		httpResponseBody.append("RESPMOD icap://"+serverName+"/info ICAP/1.0\r\n");
		httpResponseBody.append("RESPMOD icap://"+serverName+"/echo ICAP/1.0\r\n");
		httpResponseBody.append("RESPMOD icap://"+serverName+"/virus_scan ICAP/1.0\r\n");

		httpResponseBody.append("\r\n");

		StringBuilder chunkedBody = new StringBuilder()
				.append( Integer.toHexString(httpResponseBody.length()) )
				.append("\r\n")
				.append(httpResponseBody);

		StringBuilder httpResponseHeader = new StringBuilder();

		httpResponseHeader.append("HTTP/1.1 200 OK\r\n");
		httpResponseHeader.append(("Date: "+date+"\r\n"));
		httpResponseHeader.append(("Server: "+serverName+"\r\n"));
		httpResponseHeader.append(("Content-Type: text/plain\r\n"));
		httpResponseHeader.append(("Content-Length: "+httpResponseBody.length()+"\r\n"));
		httpResponseHeader.append(("Via: 1.0 "+serverName+"\r\n"));
		httpResponseHeader.append("\r\n");

		out.write(("Encapsulated: res-hdr=0, res-body="+httpResponseHeader.length()+"\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write("\r\n".getBytes(StandardCharsets.US_ASCII));

		out.write(httpResponseHeader.toString().getBytes(StandardCharsets.US_ASCII));
		out.write(chunkedBody.toString().getBytes(StandardCharsets.US_ASCII));

	}

	private void completeHandleEcho() throws Exception {

		StringBuilder encapsulatedHeaderEcho = new StringBuilder();

		int offset = 0;

		if(httpRequestHeaders.size() > 0) {
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("req-hdr=").append(offset);
			offset += httpRequestHeaders.size(); 
		}

		ByteArrayOutputStream outHttpRequestBody = new ByteArrayOutputStream();
		if( httpRequestBody.size() > 0 ) {
			outHttpRequestBody.write((Integer.toHexString(httpRequestBody.size())+"\r\n").getBytes(StandardCharsets.US_ASCII));
			outHttpRequestBody.write(httpRequestBody.toByteArray());
			outHttpRequestBody.write("\r\n".getBytes(StandardCharsets.US_ASCII));
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("req-body=").append(offset);
			offset += outHttpRequestBody.size();
		}

		if(httpResponseHeaders.size() > 0) {
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("res-hdr=").append(offset);
			offset += httpResponseHeaders.size(); 
		}

		ByteArrayOutputStream outHttpResponseBody = new ByteArrayOutputStream();
		if( httpResponseBody.size() > 0 ) {
			outHttpResponseBody.write((Integer.toHexString(httpResponseBody.size())+"\r\n").getBytes(StandardCharsets.US_ASCII));
			outHttpResponseBody.write(httpResponseBody.toByteArray());
			outHttpResponseBody.write("\r\n".getBytes(StandardCharsets.US_ASCII));
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("res-body=").append(offset);
			offset += outHttpResponseBody.size();
		}

		if( httpRequestBody.size() == 0 && httpResponseBody.size() == 0 ) {
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("null-body=").append(offset);
		}

		out.write(("Encapsulated: "+encapsulatedHeaderEcho+"\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write("\r\n".getBytes(StandardCharsets.US_ASCII));

		boolean eof = false;
		if(httpRequestHeaders.size() > 0) {
			eof = true;
			out.write(httpRequestHeaders.toByteArray());
		}

		if(outHttpRequestBody.size() > 0) {
			eof = true;
			out.write(outHttpRequestBody.toByteArray());
		}

		if(httpResponseHeaders.size() > 0) {
			eof = true;
			out.write(httpResponseHeaders.toByteArray());
		}

		if(outHttpResponseBody.size() > 0) {
			eof = true;
			out.write(outHttpResponseBody.toByteArray());
		}

		if(eof) {
			finishResponse();
		}

	}

	private void completeHandleVirusScan() throws Exception {

		StringBuilder encapsulatedHeaderEcho = new StringBuilder();

		int offset = 0;

		ByteArrayOutputStream outHttpRequestHeaders  = new ByteArrayOutputStream();
		ByteArrayOutputStream outHttpRequestBody     = new ByteArrayOutputStream();
		ByteArrayOutputStream outHttpResponseHeaders = new ByteArrayOutputStream();
		ByteArrayOutputStream outHttpResponseBody    = new ByteArrayOutputStream();

		if( icapThreatsHeader.size() > 0 ) {
			outHttpResponseHeaders.write("HTTP/1.1 403 Forbidden\r\n".getBytes(StandardCharsets.US_ASCII));
		} else {
			outHttpResponseHeaders.write("HTTP/1.1 200 OK\r\n".getBytes(StandardCharsets.US_ASCII));
		}

		outHttpResponseHeaders.write(("Server: "+serverName+"\r\n").getBytes(StandardCharsets.US_ASCII));

		StringBuilder responseMessage = new StringBuilder("");

		if( threatName != null ) {

			responseMessage.append("Virus Found: ").append(threatName).append("\n");

			outHttpResponseHeaders.write(("Content-Type: text/plain\r\n").getBytes(StandardCharsets.US_ASCII));
			outHttpResponseHeaders.write(("Content-Length: "+responseMessage.length()+"\r\n").getBytes(StandardCharsets.US_ASCII));

			outHttpResponseBody.write((Integer.toHexString(responseMessage.length())+"\r\n").getBytes(StandardCharsets.US_ASCII));
			outHttpResponseBody.write(responseMessage.toString().getBytes(StandardCharsets.US_ASCII));
			outHttpResponseBody.write("\r\n".getBytes(StandardCharsets.US_ASCII));

		}

		outHttpResponseHeaders.write(("Via: "+serverName+"\r\n").getBytes(StandardCharsets.US_ASCII));

		if( icapThreatsHeader.size() > 0 ) {
			outHttpResponseHeaders.write(icapThreatsHeader.toByteArray());
		}

		outHttpResponseHeaders.write("\r\n".getBytes(StandardCharsets.US_ASCII));

		if(outHttpRequestHeaders.size() > 0) {
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("req-hdr=").append(offset);
			offset += outHttpRequestHeaders.size();
		}

		if( outHttpRequestBody.size() > 0 ) {
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("req-body=").append(offset);
			offset += outHttpRequestBody.size();
		}

		if(outHttpResponseHeaders.size() > 0) {
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("res-hdr=").append(offset);
			offset += outHttpResponseHeaders.size();
		}

		if( outHttpResponseBody.size() > 0 ) {
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("res-body=").append(offset);
			offset += outHttpResponseBody.size();
		}

		if( outHttpRequestBody.size() == 0 && outHttpResponseBody.size() == 0 ) {
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("null-body=").append(offset);
		}

		out.write(("Encapsulated: "+encapsulatedHeaderEcho+"\r\n").getBytes(StandardCharsets.US_ASCII));
		out.write("\r\n".getBytes(StandardCharsets.US_ASCII));

		boolean eof = false;
		if(outHttpRequestHeaders.size() > 0) {
			eof = true;
			out.write(outHttpRequestHeaders.toByteArray());
		}

		if(outHttpRequestBody.size() > 0) {
			eof = true;
			out.write(outHttpRequestBody.toByteArray());
		}

		if(outHttpResponseHeaders.size() > 0) {
			eof = true;
			out.write(outHttpResponseHeaders.toByteArray());
		}

		if(outHttpResponseBody.size() > 0) {
			eof = true;
			out.write(outHttpResponseBody.toByteArray());
		}

		if(eof) {
			finishResponse();
		}

	}

	private ByteArrayOutputStream icapThreatsHeader = new ByteArrayOutputStream(); 
	private String threatName = null;

	private void findThreatsInPayload() throws Exception {
		final String environment = 
			"true".equals(System.getProperty("testMode"))
				? Optional.ofNullable(System.getProperty("test.os.name")).orElse(System.getProperty("os.name"))
				: System.getProperty("os.name");

		if(environment.toLowerCase().contains("windows")) {
			findThreatsInPayloadOnWindows();
		} else {
			findThreatsInPayloadOnLinux();
		}

	}

	private void findThreatsInPayloadOnWindows() throws Exception {

		WindowsDefenderAntivirus antivirus = new WindowsDefenderAntivirus();

		WindowsDefenderResponse response = null;

		if( httpRequestBody.size() > 0 ) {
			response = antivirus.checkThreat(httpRequestBody.toByteArray());
		} else if( httpResponseBody.size() > 0 ) {
			response = antivirus.checkThreat(httpResponseBody.toByteArray());
		}

		for( String threat: response.getThreatList() ) {
			threatName = threat;
			icapThreatsHeader.write(("X-Threat-Description: "+threatName+"\r\n").getBytes(StandardCharsets.US_ASCII));
			icapThreatsHeader.write(("X-Threat-Resolution: None\r\n").getBytes(StandardCharsets.US_ASCII));
			icapThreatsHeader.write(("X-Threat-Type: Threat\r\n").getBytes(StandardCharsets.US_ASCII));
			break;
		}

	}

	private void findThreatsInPayloadOnLinux() throws Exception {

		ClamAVCore antivirus = new ClamAVCore();

		ClamAVResponse response = null;

		if( httpRequestBody.size() > 0 ) {
			response = antivirus.checkThreat(httpRequestBody.toByteArray());
		} else if( httpResponseBody.size() > 0 ) {
			response = antivirus.checkThreat(httpResponseBody.toByteArray());
		}

		if( response.getThreat() != null ) {
			threatName = response.getThreat();
			icapThreatsHeader.write(("X-Threat-Description: "+threatName+"\r\n").getBytes(StandardCharsets.US_ASCII));
			icapThreatsHeader.write(("X-Threat-Resolution: None\r\n").getBytes(StandardCharsets.US_ASCII));
			icapThreatsHeader.write(("X-Threat-Type: Threat\r\n").getBytes(StandardCharsets.US_ASCII));
		}

	}

	//----------------------------------------

	private void readStream(byte[] out) throws IOException {

		byte[] reading = null;
		ByteArrayOutputStream cache = new ByteArrayOutputStream();

		int total = out.length;
		while(total > 0) {
			int amount = total;
			int available = in.available();
			if(amount > available) {
				amount = available;
			}
			reading = new byte[amount];
			in.read(reading);
			cache.write(reading);
			total -= amount;
		}

		new ByteArrayInputStream(cache.toByteArray()).read(out);

	}

	private void warning(String message) {
		Logger.getGlobal().warning(message);
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

	public static void main(String[] args) throws Exception {
		Worker.main(args);
	}

}
