
# Java Security Interceptor

This project is a Spring MVC-based Java application that implements a security interceptor to validate incoming HTTP requests and prevent common vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), and malicious file uploads.

## Features

- **SQL Injection Prevention**: Detects and blocks SQL injection patterns in request parameters.
- **XSS Protection**: Filters out potential cross-site scripting attacks.
- **File Upload Validation**: Allows only specific file types to be uploaded.
- **Input Sanitization**: Rejects inputs with dangerous characters, invalid UTF-8 encoding, null bytes, or newline characters.

## Technologies Used

- **Spring Framework**: Core framework for building the application and managing interceptors.
- **Java**: Programming language.
- **Regex Patterns**: Used for input validation.

---

## Files Overview

### 1. **JavaSecurityInterceptor.java**
This is the main interceptor that performs the following tasks:
- Validates request parameters for SQL Injection, XSS, and other dangerous inputs.
- Checks uploaded files for allowed extensions.
- Rejects invalid or malicious requests.

#### Key Methods:
- **`preHandle`**: Validates incoming requests before they reach the controller.
- **`validateFileInput`**: Ensures uploaded files have valid extensions.
- **`containsSQLInjection`**, **`containsXSS`**, etc.: Helper methods to check for specific vulnerabilities.

---

### 2. **WebConfig.java**
This is the Spring configuration class that:
- Registers the `JavaSecurityInterceptor` as a Spring Bean.
- Adds the interceptor to the application's request handling pipeline to validate all incoming requests.

---

## Setup Instructions

### Prerequisites
- Java 8 or higher
- Maven 3.6+
- Spring Framework 5+
- An IDE (e.g., IntelliJ IDEA, Eclipse)

---

### Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/imdeepakchahar/java-security-interceptor.git
   cd java-security-interceptor
   ```

2. Import the project into your IDE.

3. Build the project using Maven:
   ```bash
   mvn clean install
   ```

4. Run the Spring Boot application:
   ```bash
   mvn spring-boot:run
   ```

---

## Usage

1. **Interceptor Behavior**:
   - The interceptor is applied to all request paths (`/**`).
   - Malicious requests are blocked with a `400 Bad Request` response.

2. **File Uploads**:
   - Allowed file extensions: `jpg`, `jpeg`, `png`, `pdf`, `docx`.

3. **Request Validation**:
   - SQL keywords, XSS payloads, dangerous characters, invalid UTF-8, and null bytes are blocked.

4. **Customization**:
   - Modify allowed file extensions in `ALLOWED_FILE_EXTENSIONS` in `JavaSecurityInterceptor.java`.
   - Update regex patterns to match your security requirements.

---

## Project Structure

```
src/main/java/cgs/
├── config/
│   └── WebConfig.java          # Spring configuration
├── interceptor/
│   └── JavaSecurityInterceptor.java # Security interceptor
```

---

## Contact

**Author**: Deepak Kumar  
**Email**: [imchahardeepak@gmail.com](mailto:imchahardeepak@gmail.com)  
**GitHub**: [imdeepakchahar](https://github.com/imdeepakchahar)

Feel free to raise issues or contribute to this project!

---

## License

This project is open-source and available under the [MIT License](LICENSE).
