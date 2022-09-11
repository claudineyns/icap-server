package io.github.rfc3507.av.clamav;

public class ClamAVResponse {

	private String threat;
	
	public void setThreat(String threat) {
		this.threat = threat;
	}
	
	public String getThreat() {
		return threat;
	}
	
}
