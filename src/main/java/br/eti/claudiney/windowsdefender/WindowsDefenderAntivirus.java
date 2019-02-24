package br.eti.claudiney.windowsdefender;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.IOUtils;

public class WindowsDefenderAntivirus {
	
	private static String checkResult = "";
	
	public WindowsDefenderResponse checkThreat(byte[] content) 
			throws WindowsDefenderException {
		
		File file = saveContent(content);
		
		WindowsDefenderResponse response = scanContent(file);
		
		file.delete();
		
		return response;
		
	}
	
	private WindowsDefenderResponse scanContent(File file) throws WindowsDefenderException {
		
		String programFiles = System.getenv("ProgramFiles");
		
		List<String> windowsDefenderExecution = new LinkedList<>();
		windowsDefenderExecution.add(programFiles+"\\Windows Defender\\MpCmdRun.exe");
		windowsDefenderExecution.add("-Scan");
		windowsDefenderExecution.add("-ScanType");
		windowsDefenderExecution.add("3");
		windowsDefenderExecution.add("-File");
		try {
			windowsDefenderExecution.add(file.getCanonicalPath());
		} catch(Exception e) {
			throw new WindowsDefenderException(e.getMessage());
		}
		windowsDefenderExecution.add("-DisableRemediation");
		
		String[]command = windowsDefenderExecution.toArray(new String[]{});
		
		Process process = null;
		
		try {
			process = Runtime.getRuntime().exec(command);
			process.waitFor();
		} catch(Exception e) {
			throw new WindowsDefenderException(e.getMessage());
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
			throw new WindowsDefenderException(e.getMessage());
		}
		
		checkResult = new String(response.toByteArray());
		
		Pattern pattern = Pattern.compile("^Threat\\s{18}:\\s(\\S*)", Pattern.MULTILINE);
		Matcher matcher = pattern.matcher(checkResult);
		
		WindowsDefenderResponse result = new WindowsDefenderResponse();
		
		while(matcher.find()) {
			result.addThreatName(matcher.group(1));
		}
		
		return result;
		
	}
	
	private File saveContent(byte[] content) throws WindowsDefenderException {
		
		File file = new File(
				System.getProperty("java.io.tmpdir"),
//				"C:\\temp\\malware\\",
				UUID.randomUUID().toString()+".threat");
		
		OutputStream out = null;
		
		try {
			out = new FileOutputStream(file);
		} catch(Exception e) {
			throw new WindowsDefenderException(e.getMessage());
		}
		
		try {
			out.write(content);
			out.flush();
			out.close();
		} catch(Exception e) {
			throw new WindowsDefenderException(e.getMessage());
		} finally {
			try { out.close(); } catch(IOException f) {}
		}
		
		return file;
		
	}
	
}
