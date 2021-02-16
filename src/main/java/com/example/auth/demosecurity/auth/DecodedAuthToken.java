package com.example.auth.demosecurity.auth;

import java.time.LocalDateTime;
import java.util.List;

public class DecodedAuthToken {

    private List<String> roles;
    private List<String> permissions;

    private String issuer;
    private List<String> audience;
    private LocalDateTime expiresAt;
    private LocalDateTime issuedAt;
    private String client_Id;
	
	public List<String> getRoles() {
		return roles;
	}
	public void setRoles(List<String> roles) {
		this.roles = roles;
	}
	public List<String> getPermissions() {
		return permissions;
	}
	public void setPermissions(List<String> permissions) {
		this.permissions = permissions;
	}
	public String getIssuer() {
		return issuer;
	}
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}
	public List<String> getAudience() {
		return audience;
	}
	public void setAudience(List<String> audience) {
		this.audience = audience;
	}
	public LocalDateTime getExpiresAt() {
		return expiresAt;
	}
	public void setExpiresAt(LocalDateTime expiresAt) {
		this.expiresAt = expiresAt;
	}
	public LocalDateTime getIssuedAt() {
		return issuedAt;
	}
	public void setIssuedAt(LocalDateTime issuedAt) {
		this.issuedAt = issuedAt;
	}
	public String getClient_Id() {
		return client_Id;
	}
	public void setClient_Id(String client_Id) {
		this.client_Id = client_Id;
	}

	@Override
	public String toString() {
		return "DecodedAuthToken [audience=" + audience + ", client_Id=" + client_Id + ", expiresAt=" + expiresAt
				+ ", issuedAt=" + issuedAt + ", issuer=" + issuer + ", permissions="
				+ permissions + ", roles=" + roles + "]";
	}

}
