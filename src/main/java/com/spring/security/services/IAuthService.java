package com.spring.security.services;

import com.spring.security.persistence.dtos.LoginDTO;
import com.spring.security.persistence.entities.UserEntity;

import java.util.HashMap;

public interface IAuthService {

    public HashMap<String, String> login(LoginDTO loginRequest) throws Exception;
    public HashMap<String, String> register(UserEntity user) throws Exception;
}
