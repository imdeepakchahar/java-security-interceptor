package app.config; // Your package name

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import app.interceptor.JavaSecurityInterceptor;

/**
 * WebConfig
 * 
 * This configuration class sets up the Spring MVC web context.
 * It registers the JavaSecurityInterceptor to validate incoming requests for security risks.
 * 
 * Author: Deepak Kumar
 * Email: imchahardeepak@gmail.com
 * GitHub: https://github.com/imdeepakchahar/java-security-interceptor
 */
@Configuration
@EnableWebMvc
public class WebConfig implements WebMvcConfigurer {

    /**
     * Defines a JavaSecurityInterceptor bean.
     * 
     * @return an instance of JavaSecurityInterceptor
     */
    @Bean
    public JavaSecurityInterceptor javaSecurityInterceptor() {
        return new JavaSecurityInterceptor();
    }

    /**
     * Adds the JavaSecurityInterceptor to the application's interceptor registry.
     * This ensures that all incoming requests are processed through the interceptor for validation.
     * 
     * @param registry the registry to which the interceptor is added
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(javaSecurityInterceptor())
                .addPathPatterns("/**"); // Applies the interceptor to all request paths.
    }
}
