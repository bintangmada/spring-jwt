package com.bintang.controller;

import com.bintang.dto.LoginRequest;
import com.bintang.dto.RegisterRequest;
import com.bintang.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class AuthController {

    @Autowired private AuthService authService;

    @GetMapping({"/", "/login"})
    public String loginPage(){
        return "login";
    }

    @GetMapping("/register")
    public String registerPage(){
        return "register";
    }

    @PostMapping("/register")
    public String register(@ModelAttribute RegisterRequest req, Model model){
        try{
            authService.register(req);
            return "redirect:/login";
        }catch (Exception e){
            model.addAttribute("error", e.getMessage());
            return "register";
        }
    }

    @PostMapping("/do-login")
    public String login(@ModelAttribute LoginRequest req, Model model, HttpServletResponse response){
        try{
            String jwt = authService.login(req);
            Cookie cookie = new Cookie("token", jwt);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            response.addCookie(cookie);
            return "redirect:/dashboard";
        }catch (Exception e){
            model.addAttribute("error", "login failed");
            return "login";
        }
    }

    @GetMapping("/dashboard")
    public String dashboard(){
        return "/dashboard";
    }
}
