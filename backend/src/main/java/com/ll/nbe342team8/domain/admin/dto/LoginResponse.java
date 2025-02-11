package com.ll.nbe342team8.domain.admin.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class LoginResponse { // 로그인 응답 DTO
	private String token; // JWT 토큰
	private String refreshToken; // JWT 리프레시 토큰
}
