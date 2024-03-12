package com.auth.springsecurity;

import com.auth.springsecurity.entities.Role;
import com.auth.springsecurity.entities.User;
import com.auth.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class SpringsecurityApplication implements CommandLineRunner {

	@Autowired
	private  UserRepository userRepository;


	public static void main(String[] args) {
		SpringApplication.run(SpringsecurityApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		User admin=userRepository.findByRole(Role.ADMIN);
		if(admin==null){
			User user=new User();
			user.setFirstname("Admin");
			user.setLastname("Admin");
			user.setEmail("admin@yopmail.com");
			user.setPassword(new BCryptPasswordEncoder().encode("admin"));
			user.setRole(Role.ADMIN);
			userRepository.save(user);
		}
	}
}
