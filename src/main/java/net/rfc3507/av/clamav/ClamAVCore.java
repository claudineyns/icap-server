package net.rfc3507.av.clamav;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.IOUtils;

public class ClamAVCore {
	
	private final String id = UUID.randomUUID().toString();
	
	public String getId() {
		return id;
	}
	
	public ClamAVResponse checkThreat(byte[] content) 
			throws ClamAVException {
		
		File file = saveContent(content);
		
		ClamAVResponse response = scanContent(file);
		
		file.delete();
		
		return response;
		
	}
	
	private File saveContent(byte[] content) 
			throws ClamAVException {
		
		File workDir = new File(
				System.getProperty("java.io.tmpdir"), getId()); 
		workDir.mkdirs();
		
		File file = new File(workDir, "file.threat");
		
		OutputStream out = null;
		
		try {
			out = new FileOutputStream(file);
		} catch(Exception e) {
			throw new ClamAVException(e.getMessage());
		}
		
		try {
			out.write(content);
			out.flush();
			out.close();
		} catch(Exception e) {
			throw new ClamAVException(e.getMessage());
		} finally {
			try { out.close(); } catch(IOException f) {}
		}
		
		return file;
		
	}
	
	private ClamAVResponse scanContent(File file) throws ClamAVException {
		
		String path = file.getParent();
		Logger.getGlobal().info("Scanning file: " + path+file.getName() + "...");
		Logger.getGlobal().info("Scanning path: " + path + "...");
		
		List<String> daemonExec = new LinkedList<>();
		daemonExec.add("/usr/bin/clamscan");
		daemonExec.add("-vir");
		daemonExec.add(path);
		
		String[]command = daemonExec.toArray(new String[]{});
		
		Process process = null;
		
		try {
			process = Runtime.getRuntime().exec(command);
			process.waitFor();
		} catch(Exception e) {
			throw new ClamAVException(e.getMessage());
		}
		
		InputStream input = null;
		
		input = process.getInputStream();
		if( input == null ) {
			input = process.getErrorStream();
		}
		
		ByteArrayOutputStream response = new ByteArrayOutputStream();
		
		try {
			IOUtils.copy(input, response);
		} catch(IOException e) {
			throw new ClamAVException(e.getMessage());
		}
		
		String checkResult = null;
		try {
			checkResult = new String(response.toByteArray(), "ascii");
		} catch(UnsupportedEncodingException e) {}
		
		Pattern pattern = Pattern.compile(
				"\\s(\\S*)\\sFOUND$",
				Pattern.MULTILINE);
		
		Matcher matcher = pattern.matcher(checkResult);
		
		ClamAVResponse result = new ClamAVResponse();
		
		while(matcher.find()) {
			result.setThreat(matcher.group(1));
		}
		
		return result;
		
	}

}
