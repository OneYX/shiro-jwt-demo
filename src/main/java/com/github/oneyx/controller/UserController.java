package com.github.oneyx.controller;

import com.alibaba.fastjson.JSON;
import com.github.oneyx.entity.UserInfo;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @RequiresRoles("admin")
    @RequestMapping("/user")
    public String userInfo() {
        UserInfo userInfo = (UserInfo) SecurityUtils.getSubject().getPrincipal();
        return JSON.toJSONString(userInfo);
    }
}
