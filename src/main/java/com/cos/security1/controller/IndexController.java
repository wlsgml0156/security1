package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
//    public @ResponseBody String testLogin(Authentication authentication, @AuthenticationPrincipal UserDetails userDetails){
    public @ResponseBody String testLogin(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails){
        System.out.println("/test/login");
//        System.out.println("authentication"+authentication.getPrincipal());
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication : "+principalDetails.getUser());
//        System.out.println("authentication"+userDetails.getUsername());
        System.out.println("userDetails : "+userDetails.getUser());


        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody String testLogin(Authentication authentication,@AuthenticationPrincipal OAuth2User oAuth){
        System.out.println("/test/login");

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("testLogin() - authentication"+oAuth2User.getAuthorities());
        System.out.println("testLogin() - authentication"+oAuth.getAuthorities());

        return "OAuth 세션 정보 확인하기";
    }

    @GetMapping({"","/"})
    public String index(){
        // 머스테치 기본폴더 src/main/resources/ 로 잡힌다.
        // 뷰리졸버 설정 : templates (prefix), .mustache(suffix)
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails){
        System.out.println("principalDetails : "+ principalDetails.getUser());
        return "uesr";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager(){
        return "manager";
    }

    // 스프링시큐리티 해당주소를 낚아채버린다.-> SecurityConfig 파일 생성 후 스프링시큐리티login페이지 작동 안함
    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user){
        System.out.println(user);
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user); // 회원가입 잘됨. but : 1234 -> 시큐리티로 로그인 할 수 x, 이유는 비번이 암호화가 안되어있기 때문에
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody String data(){
        return "데이터정보";
    }

}
