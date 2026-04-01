package com.example.memberssecurity.member.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class HomeController {

    @GetMapping("/home/GPT-Home")
    public String gptHome(@RequestParam(value = "token", required = false) String token,
                          @RequestParam(value = "error", required = false) String error,
                          Model model) {
        model.addAttribute("token", token);
        model.addAttribute("error", error);
        return "home/GPT-home";
    }
}
