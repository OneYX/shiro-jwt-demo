package com.github.oneyx.shrio;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JWTUser {
    private Integer userId;
    private String username;
}
