package com.proje.model;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;

@Entity
@Table(name = "user")   // Mysql tablosunun olusturuldugu kisim
public class DAOUser {
	
	//Kullan�c�dan de�erler almak ve veritaban�na eklemek i�in DAO katman�na iletmeui sa�layan s�n�f
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	@Column
	private String username;
	@Column
	@JsonIgnore
	private String password;

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

}