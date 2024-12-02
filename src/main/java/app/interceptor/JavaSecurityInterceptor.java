package app.interceptor;  // Your package name

import org.springframework.web.multipart.MultipartHttpServletRequest;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.regex.Pattern;

/**
 * JavaSecurityInterceptor
 *
 * This interceptor validates HTTP requests to safeguard against security vulnerabilities
 * such as SQL Injection, Cross-Site Scripting (XSS), and malicious file uploads.
 * It performs validation checks on request parameters and file uploads, rejecting
 * any that appear to be malicious or invalid.
 *
 * Author: Deepak Kumar
 * Email: imchahardeepak@gmail.com
 * GitHub: https://github.com/imdeepakchahar/java-security-interceptor
 */
public class JavaSecurityInterceptor implements HandlerInterceptor {

    // Pattern to detect SQL injection keywords in request parameters.
    private static final String SQL_INJECTION_PATTERN =
            "(?i).*\\b(select|insert|drop|update|delete|exec|union|create|alter|truncate|declare|--|\\/\\*|\\*\\/|;|where|having|limit|group)\\b.*";

    // Pattern to detect dangerous characters such as <, >, ', ", %, and &.
    private static final String DANGEROUS_CHARACTERS_PATTERN = ".*[<>'\"%&].*";

    // Pattern to ensure input is valid UTF-8 encoded.
    private static final String UTF8_PATTERN = "[\\u0000-\\u007F]+";

    // Pattern to identify potential XSS payloads in the input.
    private static final String XSS_PATTERN = "<.*?>";

    // Patterns to detect newline characters and null bytes in input.
    private static final String NEWLINE_PATTERN = "[\\r\\n]";
    private static final String NULL_BYTE_PATTERN = "%00";

    // List of allowed file extensions for uploaded files.
    private static final String[] ALLOWED_FILE_EXTENSIONS = {"jpg", "jpeg", "png", "pdf", "docx"};

    /**
     * Pre-handle method to validate HTTP requests before they reach the controller.
     *
     * @param request  the HTTP request object
     * @param response the HTTP response object
     * @param handler  the handler for the request
     * @return true if the request passes all validations, false otherwise
     * @throws Exception in case of any unexpected errors
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        Enumeration<String> parameterNames = request.getParameterNames();

        // Validate uploaded files for allowed extensions.
        if (!validateFileInput(request)) {
            response.sendError(400, "Invalid file type detected.");
            return false;
        }

        // Iterate through all request parameters to validate their content.
        while (parameterNames.hasMoreElements()) {
            String paramName = parameterNames.nextElement();
            String paramValue = request.getParameter(paramName);

            if (containsSQLInjection(paramValue)) {
                response.sendError(400, "SQL Injection detected in parameter: " + paramName);
                return false;
            }

            if (containsDangerousCharacters(paramValue)) {
                response.sendError(400, "Dangerous characters detected in parameter: " + paramName);
                return false;
            }

            if (containsXSS(paramValue)) {
                response.sendError(400, "XSS attack detected in parameter: " + paramName);
                return false;
            }

            if (!isValidUTF8(paramValue)) {
                response.sendError(400, "Invalid UTF-8 encoding detected in parameter: " + paramName);
                return false;
            }

            if (containsNewLine(paramValue) || containsNullByte(paramValue)) {
                response.sendError(400, "Invalid characters detected in parameter: " + paramName);
                return false;
            }
        }

        return true;
    }

    /**
     * Validates uploaded files for allowed extensions.
     *
     * @param request the HTTP request object
     * @return true if all files have valid extensions, false otherwise
     * @throws IOException in case of file handling errors
     */
    private boolean validateFileInput(HttpServletRequest request) throws IOException {
        if (request instanceof MultipartHttpServletRequest) {
            MultipartHttpServletRequest multiRequest = (MultipartHttpServletRequest) request;
 
            java.util.Iterator<String> fileNames = multiRequest.getFileNames();
            while (fileNames.hasNext()) {
                String fileName = fileNames.next(); 
                MultipartFile file = multiRequest.getFile(fileName);

                if (file != null && !file.isEmpty()) {
                    // Get the actual file name
                    String originalFileName = file.getOriginalFilename();
                    String fileExtension = getFileExtension(originalFileName);

                    //System.out.println("Field Name: " + fileName);
                    //System.out.println("Original File Name: " + originalFileName);
                    //System.out.println("File Extension: " + fileExtension);

                    if (!isValidFileExtension(fileExtension)) {
                        return false; // Invalid file extension
                    }
                }
            }
        }
        return true;
    }

    /**
     * Extracts the file extension from a filename.
     *
     * @param filename the name of the file
     * @return the file extension, or an empty string if none is found
     */
    private String getFileExtension(String filename) {
        if (filename == null || filename.isEmpty()) return "";
        int lastIndexOfDot = filename.lastIndexOf(".");
        return (lastIndexOfDot == -1) ? "" : filename.substring(lastIndexOfDot + 1);
    }

    /**
     * Checks if the file extension is allowed.
     *
     * @param fileExtension the file extension to check
     * @return true if the extension is allowed, false otherwise
     */
    private boolean isValidFileExtension(String fileExtension) {
        for (String allowedExtension : ALLOWED_FILE_EXTENSIONS) {
            if (allowedExtension.equalsIgnoreCase(fileExtension)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Validates input for SQL injection patterns.
     *
     * @param input the input string to validate
     * @return true if the input contains SQL injection patterns, false otherwise
     */
    private boolean containsSQLInjection(String input) {
        return input != null && Pattern.compile(SQL_INJECTION_PATTERN).matcher(input).matches();
    }

    /**
     * Checks if the input contains dangerous characters.
     *
     * @param input the input string to validate
     * @return true if dangerous characters are detected, false otherwise
     */
    private boolean containsDangerousCharacters(String input) {
        return input != null && Pattern.compile(DANGEROUS_CHARACTERS_PATTERN).matcher(input).matches();
    }

    /**
     * Validates input for Cross-Site Scripting (XSS) patterns.
     *
     * @param input the input string to validate
     * @return true if XSS patterns are detected, false otherwise
     */
    private boolean containsXSS(String input) {
        return input != null && Pattern.compile(XSS_PATTERN).matcher(input).matches();
    }

    /**
     * Checks if the input is valid UTF-8 encoded.
     *
     * @param input the input string to validate
     * @return true if the input is valid UTF-8 encoded, false otherwise
     */
    private boolean isValidUTF8(String input) {
        return input == null || Pattern.compile(UTF8_PATTERN).matcher(input).matches();
    }

    /**
     * Checks if the input contains newline characters.
     *
     * @param input the input string to validate
     * @return true if newline characters are detected, false otherwise
     */
    private boolean containsNewLine(String input) {
        return input != null && Pattern.compile(NEWLINE_PATTERN).matcher(input).matches();
    }

    /**
     * Checks if the input contains null byte characters.
     *
     * @param input the input string to validate
     * @return true if null byte characters are detected, false otherwise
     */
    private boolean containsNullByte(String input) {
        return input != null && input.contains(NULL_BYTE_PATTERN);
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
        // This method can be used for additional processing after the controller handles the request.
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        // This method can be used for cleanup activities after the request has been completed.
    }
}
