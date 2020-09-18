package com.proje.model;

import java.io.Serializable;

public class JwtResponse implements Serializable {

	private static final long serialVersionUID = -8091879091924046844L;
	private final String jwttoken;

	public JwtResponse(String jwttoken) {
		this.jwttoken = jwttoken;
	}
	
	//Bu s�n�fta kullan�c�ya olu�turulan tokenin verildi�i s�n�ft�r

	public String getToken() {
		return this.jwttoken;
	}
}