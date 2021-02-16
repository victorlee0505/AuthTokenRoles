package com.example.auth.demosecurity.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BaseController {

	private static final Logger LOG = LoggerFactory.getLogger(BaseController.class);

    @GetMapping(produces=MediaType.APPLICATION_JSON_VALUE)
    public String welcome(){
        LOG.info("api: welcome");
        return "Hello World";
    }

	@GetMapping(path="/user", produces=MediaType.APPLICATION_JSON_VALUE)
    public String user(){
        LOG.info("api: user");
        return "Welcome: User";
    }
	

    @GetMapping(path="/admin", produces=MediaType.APPLICATION_JSON_VALUE)
	public String admin() {
        LOG.info("api: admin");
        return "Welcom: Admin";
	}

}
