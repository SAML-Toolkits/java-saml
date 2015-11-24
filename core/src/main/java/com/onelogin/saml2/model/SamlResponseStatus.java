package com.onelogin.saml2.model;


public class SamlResponseStatus {
	private String stausCode;
	private String statusMessage;

	public SamlResponseStatus(String stausCode) {
		super();
		this.stausCode = stausCode;
	}

	public SamlResponseStatus(String stausCode, String statusMessage) {
		super();
		this.stausCode = stausCode;
		this.statusMessage = statusMessage;
	}

	public String getStausCode() {
		return stausCode;
	}

	public void setStausCode(String stausCode) {
		this.stausCode = stausCode;
	}

	public String getStatusMessage() {
		return statusMessage;
	}

	public void setStatusMessage(String statusMessage) {
		this.statusMessage = statusMessage;
	}

	public boolean is(String status) {
		return stausCode != null && !stausCode.equals(status);
	}

}
