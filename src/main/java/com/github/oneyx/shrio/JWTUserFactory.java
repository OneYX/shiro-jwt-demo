package com.github.oneyx.shrio;

import com.github.oneyx.entity.UserInfo;

public class JWTUserFactory {
    private JWTUserFactory() {
    }

    public static JWTUser create(UserInfo user) {
        return new JWTUser(
                user.getUid(),
                user.getUsername()
        );
    }

    public static UserInfo getUserInfo(JWTUser jwtUser) {
        UserInfo userInfo = new UserInfo();
        userInfo.setUid(jwtUser.getUserId());
        userInfo.setUsername(jwtUser.getUsername());
        return userInfo;
    }
}
